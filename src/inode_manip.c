#include "filesys.h"

#include <string.h>
#include <assert.h>

#include "utility.h"
#include "debug.h"

#define INDIRECT_DBLOCK_INDEX_COUNT (DATA_BLOCK_SIZE / sizeof(dblock_index_t) - 1)
#define INDIRECT_DBLOCK_MAX_DATA_SIZE ( DATA_BLOCK_SIZE * INDIRECT_DBLOCK_INDEX_COUNT )

#define NEXT_INDIRECT_INDEX_OFFSET (DATA_BLOCK_SIZE - sizeof(dblock_index_t))

// ----------------------- UTILITY FUNCTION ----------------------- //
static fs_retcode_t getAllocDbi(filesystem_t *fs, inode_t *inode, size_t block, dblock_index_t *dbi){
    if(!fs || !inode || !dbi){
        return INVALID_INPUT;
    }
    //dir else
    if(block < INODE_DIRECT_BLOCK_COUNT){
        dblock_index_t *db = &inode->internal.direct_data[block];
        if(*db == 0){
            fs_retcode_t retcode = claim_available_dblock(fs, db);
            if(retcode != SUCCESS){
                return retcode;
            }
        }
        *dbi = *db;
        return SUCCESS;
    }
    
    //indir
    size_t indirect_idx = block - INODE_DIRECT_BLOCK_COUNT;
    if(inode->internal.indirect_dblock == 0){
        fs_retcode_t retcode = claim_available_dblock(fs, &inode->internal.indirect_dblock);
        if(retcode != SUCCESS){
            return retcode;
        }
    }

    dblock_index_t ibi = inode->internal.indirect_dblock;
    size_t ibi_used = 0;
    while(1){
        size_t ib_byte = indirect_idx % INDIRECT_DBLOCK_INDEX_COUNT;
        size_t ib = indirect_idx / INDIRECT_DBLOCK_INDEX_COUNT;
        if(ibi_used < ib){
            dblock_index_t *next = cast_dblock_ptr(&fs->dblocks[ibi * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]);
            //allocing ne w ib after
            if(*next == 0){
                dblock_index_t new_ib;
                fs_retcode_t retcode = claim_available_dblock(fs, &new_ib);
                if(retcode != SUCCESS){
                    return retcode;
                }
                *next = new_ib;
            }
            ibi = *next;
            ibi_used++;
            continue;
        }

        size_t offset = ib_byte * sizeof(dblock_index_t);
        dblock_index_t *db = cast_dblock_ptr(&fs ->dblocks[ibi * DATA_BLOCK_SIZE + offset]);
        if(*db == 0){
            fs_retcode_t retcode = claim_available_dblock(fs, db);
            if(retcode != SUCCESS){
                return retcode;
            }
        }
        *dbi = *db;
        return SUCCESS;
    }
}

 static fs_retcode_t getDbi(filesystem_t *fs, inode_t *inode, size_t block, dblock_index_t *dbi){
    if(!fs || !inode || !dbi){
        return INVALID_INPUT;
    }
    if(block < INODE_DIRECT_BLOCK_COUNT){
        dblock_index_t db = inode->internal.direct_data[block];
        if(db == 0){
            return DBLOCK_UNAVAILABLE;
        }
        *dbi = db;
        return SUCCESS;
    }
    size_t indirect_idx = block - INODE_DIRECT_BLOCK_COUNT;
    if(inode -> internal.indirect_dblock == 0){
        return DBLOCK_UNAVAILABLE;
    }

    dblock_index_t ibi = inode->internal.indirect_dblock;
    size_t ibi_used = 0;
    while(1){
        size_t ib_byte = indirect_idx % INDIRECT_DBLOCK_INDEX_COUNT;
        size_t ib = indirect_idx / INDIRECT_DBLOCK_INDEX_COUNT;
        if(ibi_used < ib){
            dblock_index_t *next = cast_dblock_ptr(&fs->dblocks[ibi * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]);
            if(*next == 0){
                return DBLOCK_UNAVAILABLE;
            }
            ibi = *next;
            ibi_used++;
            continue;
        }

        size_t offset = ib_byte * sizeof(dblock_index_t);
        dblock_index_t *dbp = cast_dblock_ptr(&fs->dblocks[ibi * DATA_BLOCK_SIZE + offset]);
        if(*dbp == 0){
            return DBLOCK_UNAVAILABLE;
        }
        *dbi = *dbp;
        return SUCCESS;
    }
}

//helper function to free all indirect blocks
static void freeAllIbs(filesystem_t *fs, dblock_index_t first){
    if(first == 0){
        return;
    }

    dblock_index_t current = first;
    while(current != 0){
        for(size_t i = 0; i < INDIRECT_DBLOCK_INDEX_COUNT; i++){
            size_t offset = i * sizeof(dblock_index_t);
            dblock_index_t *db = cast_dblock_ptr(&fs->dblocks[current * DATA_BLOCK_SIZE + offset]);
            if(*db != 0){
                byte *p = &fs->dblocks[*db * DATA_BLOCK_SIZE];
                release_dblock(fs, p);
                *db = 0;
            }
        }

        dblock_index_t *next = cast_dblock_ptr(&fs->dblocks[current * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]);
        dblock_index_t next_index = *next;
        byte *ib = &fs->dblocks[current * DATA_BLOCK_SIZE];
        release_dblock(fs, ib);
        current = next_index;
    }
}
static fs_retcode_t freeLast(filesystem_t *fs, inode_t *inode){
    if(!fs || !inode){
        return INVALID_INPUT;
    }
    size_t old_size = inode->internal.file_size;
    if(old_size == 0){
        return SUCCESS;
    }
    
    size_t block_total = (old_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE;
    if(block_total == 0){
        return SUCCESS;
    }
    size_t last_db = block_total - 1;
    
    //remove remaining db
    if(last_db < INODE_DIRECT_BLOCK_COUNT){
        dblock_index_t dbi = inode->internal.direct_data[last_db];
        if(dbi != 0){
            byte *p = &fs->dblocks[dbi * DATA_BLOCK_SIZE];
            release_dblock(fs, p);// fs dblock (dbp)
            inode -> internal.direct_data[last_db] = 0;            
        }
    }
    //indir 
    else{
        size_t indirect = last_db - INODE_DIRECT_BLOCK_COUNT;
        dblock_index_t ib = inode->internal.indirect_dblock;
        if(ib == 0){
            inode -> internal.file_size = 0;
            return SUCCESS;
        }

        size_t iblock = indirect / INDIRECT_DBLOCK_INDEX_COUNT;
        size_t iblock_off = indirect % INDIRECT_DBLOCK_INDEX_COUNT;
        dblock_index_t prev = 0;
        for(size_t i = 0; i < iblock; i++){
            dblock_index_t *next = cast_dblock_ptr(&fs->dblocks[ib * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]);
            if(*next == 0){
                return SUCCESS;
            }
            prev = ib;
            ib = *next;
        }
        size_t offset = iblock_off * sizeof(dblock_index_t);
        dblock_index_t *ibp = cast_dblock_ptr(&fs->dblocks[ib * DATA_BLOCK_SIZE + offset]);
        if(*ibp != 0){
            byte *data_ptr = &fs->dblocks[*ibp * DATA_BLOCK_SIZE];
            release_dblock(fs, data_ptr);
            *ibp = 0;
        }
        
        int empty = 1;
        for(size_t i = 0; i < INDIRECT_DBLOCK_INDEX_COUNT; i++){
            size_t off = i * sizeof(dblock_index_t);
            dblock_index_t full = *cast_dblock_ptr(&fs->dblocks[ib * DATA_BLOCK_SIZE + off]);
            if(full != 0){
                empty = 0;
                break;
            }
        }
        if(empty){
            dblock_index_t *next = cast_dblock_ptr(&fs->dblocks[ib * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]); 
            dblock_index_t next_idx = *next;
            byte *p = &fs->dblocks[ib * DATA_BLOCK_SIZE];
            release_dblock(fs, p);

            if(prev == 0 && iblock == 0){
                inode->internal.indirect_dblock = next_idx;
            }
            else{
                dblock_index_t *next_prev = cast_dblock_ptr(&fs->dblocks[prev * DATA_BLOCK_SIZE + NEXT_INDIRECT_INDEX_OFFSET]);
                *next_prev = next_idx;
            }
        }
    }
    return SUCCESS;
}

// ----------------------- CORE FUNCTION ----------------------- //
//part 1 
fs_retcode_t inode_write_data(filesystem_t *fs, inode_t *inode, void *data, size_t n)
{

    //Check for valid input
    if(!fs || !inode || !data){
        return INVALID_INPUT;
    }
    if(n == 0){
        return SUCCESS;
    }
    // do we have enough dblocks to store the data. if not, error. 
    size_t old_size = inode->internal.file_size;
    size_t new_size = old_size + n;

    size_t old_blocks = calculate_necessary_dblock_amount(old_size);
    size_t new_blocks = calculate_necessary_dblock_amount(new_size);
    size_t need_blocks = (new_blocks > old_blocks) ? (new_blocks - old_blocks) : 0;
    if(need_blocks > 0 && need_blocks > available_dblocks(fs)){
        return INSUFFICIENT_DBLOCKS;
    }
    // fill the direct nodes if necessary (helper function)
    // fill the indirect nodes if necessary (helper function)
    size_t n_writ = 0;
    const byte *src = (const byte *)data;

    while(n_writ < n){
        size_t offset = old_size + n_writ;
        size_t block = offset / DATA_BLOCK_SIZE;
        size_t block_byte = offset % DATA_BLOCK_SIZE;
        size_t rem_bspace = DATA_BLOCK_SIZE - block_byte;
        size_t coppied = (n - n_writ < rem_bspace) ? (n - n_writ) : rem_bspace;

        dblock_index_t dbi = 0;
        fs_retcode_t retcode = getAllocDbi(fs, inode, block, &dbi);
        if(retcode != SUCCESS){
            return retcode;
        }

        byte *bp = &fs->dblocks[dbi * DATA_BLOCK_SIZE + block_byte];
        memcpy(bp, &src[n_writ], coppied);

        n_writ += coppied;
    }

    inode->internal.file_size = new_size;
    return SUCCESS;
}

fs_retcode_t inode_read_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n, size_t *bytes_read)
{
    
    //check to make sure inputs are valid
    //Check for valid input
    if(!fs || !inode || !bytes_read || !buffer){
        return INVALID_INPUT;
    }
    //for 0 to n, use the helper function to read and copy 1 byte at a time
    *bytes_read = 0;
    size_t file_size = inode -> internal.file_size;
    if(offset >= file_size || n == 0){
        return SUCCESS;
    }

    size_t readable = file_size - offset;
    size_t remains = (n < readable) ? n : readable;
    size_t total = 0;
    byte *dst = (byte*)buffer;
    while(total < remains){
        size_t off = offset + total;
        size_t block = off / DATA_BLOCK_SIZE;
        size_t block_byte = off % DATA_BLOCK_SIZE;
        size_t rem_bspace = DATA_BLOCK_SIZE - block_byte;
        size_t read = (remains - total < rem_bspace) ? (remains - total) : rem_bspace;

        dblock_index_t dbi;
        fs_retcode_t retcode = getDbi(fs, inode, block, &dbi);
        if(retcode != SUCCESS){
            memset(&dst[total],0,read);
        }
        else{
            byte *src = &fs->dblocks[dbi * DATA_BLOCK_SIZE + block_byte];
            memcpy(&dst[total],src,read);
        }
        total += read;
    }
    *bytes_read = total;
    return SUCCESS;
}

fs_retcode_t inode_modify_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n)
{

    //check to see if the input is valid
    if(!fs || !inode || !buffer){
        return INVALID_INPUT;
    }
    size_t file_size = inode->internal.file_size;
    if(offset > file_size){
        return INVALID_INPUT;
    }
    if(n == 0){
        return SUCCESS;
    }
    //calculate the final filesize and verify there are enough blocks to support it
    //use calculate_necessary_dblock_amount and available_dblocks
    size_t overwrite = offset + n;
    if(overwrite <= file_size){
        size_t n_writ = 0;
        byte *src = (byte*)buffer;
        while(n_writ < n){
            size_t off = offset + n_writ;
            size_t block = off / DATA_BLOCK_SIZE;
            size_t block_byte = off % DATA_BLOCK_SIZE;
            size_t rem_bspace = DATA_BLOCK_SIZE - block_byte;
            size_t coppied = ((n - n_writ) < rem_bspace) ? (n - n_writ) : rem_bspace;

            dblock_index_t dbi;
            fs_retcode_t retcode = getAllocDbi(fs, inode, block, &dbi);
            if(retcode != SUCCESS){
                return retcode;
    
            }
            byte *bp = &fs->dblocks[dbi * DATA_BLOCK_SIZE + block_byte];
            memcpy(bp,&src[n_writ],coppied);
            n_writ += coppied;
        }
        return SUCCESS;
    }
    else if(overwrite > file_size){
        size_t old_size = file_size;
        size_t new_size = overwrite;

        size_t old_blocks = calculate_necessary_dblock_amount(old_size);
        size_t new_blocks = calculate_necessary_dblock_amount(new_size);
        size_t need_blocks = (new_blocks > old_blocks) ? (new_blocks - old_blocks) : 0;
        if(need_blocks > 0 && need_blocks > available_dblocks(fs)){
            return INSUFFICIENT_DBLOCKS;
        }
        size_t n_writ = 0;
        byte *src = (byte *)buffer;
        size_t old_data = old_size - offset;
       
        while(n_writ < old_data){
            size_t off = offset + n_writ;
            size_t block = off / DATA_BLOCK_SIZE;
            size_t block_byte = off % DATA_BLOCK_SIZE;
            size_t rem_bspace = DATA_BLOCK_SIZE - block_byte;
            size_t coppied = ((old_data - n_writ) < rem_bspace) ? (old_data - n_writ) : rem_bspace;

            dblock_index_t dbi;
            fs_retcode_t retcode = getAllocDbi(fs, inode, block, &dbi);
            if(retcode != SUCCESS){
                return retcode;
    
            }
            byte *bp = &fs->dblocks[dbi * DATA_BLOCK_SIZE + block_byte];
            memcpy(bp,&src[n_writ],coppied);
            n_writ += coppied;
        }
        size_t new_data = n - n_writ;
        fs_retcode_t retcode = inode_write_data(fs, inode, &src[n_writ], new_data); //For the new data, call "inode_write_data" and return
        if(retcode != SUCCESS){
            return retcode;
        }
        return SUCCESS;
    }

    //Write to existing data in your inode
return SUCCESS;
    //For the new data, call "inode_write_data" and return
}

fs_retcode_t inode_shrink_data(filesystem_t *fs, inode_t *inode, size_t new_size)
{ 
    //check to see if inputs are in valid range
    if(!fs || !inode ){
        return INVALID_INPUT;
    }
    size_t old_size = inode->internal.file_size;
    if(new_size > old_size){
        return INVALID_INPUT;
    }
    if(new_size == old_size){
        return SUCCESS;
    }
    //Calculate how many blocks to remove
    size_t old_blocks = (old_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE;
    size_t new_blocks = (new_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE;
    //helper function to free all indirect blocks
    while(old_blocks > new_blocks){
        fs_retcode_t retcode = freeLast(fs, inode);
        if(retcode != SUCCESS){
            return retcode;
        }
        old_blocks--;
    }
//remove the remaining direct dblocks
    //update filesize and return
    inode->internal.file_size = new_size;
    return SUCCESS;
}

// make new_size to 0
fs_retcode_t inode_release_data(filesystem_t *fs, inode_t *inode)
{
    if(!fs || !inode){
        return INVALID_INPUT;
    }

    for(size_t i = 0; i < INODE_DIRECT_BLOCK_COUNT; i++){
        dblock_index_t db = inode->internal.direct_data[i];
        if(db != 0){
            byte *p = &fs->dblocks[db * DATA_BLOCK_SIZE];
            release_dblock(fs, p);
            inode -> internal.direct_data[i] = 0;
        }
    }
    freeAllIbs(fs, inode->internal.indirect_dblock);
    inode->internal.indirect_dblock = 0;
    inode->internal.file_size = 0;
    return SUCCESS;
}
