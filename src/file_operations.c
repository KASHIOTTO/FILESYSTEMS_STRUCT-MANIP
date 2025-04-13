#include "filesys.h"
#include "debug.h"
#include "utility.h"

#include <string.h>

#define DIRECTORY_ENTRY_SIZE (sizeof(inode_index_t) + MAX_FILE_NAME_LEN)
#define DIRECTORY_ENTRIES_PER_DATABLOCK (DATA_BLOCK_SIZE / DIRECTORY_ENTRY_SIZE)


static size_t tokenize(char *buffer, char *tokens[], size_t depth_max);
static int findChild(filesystem_t *fs, inode_t *dirnode, const char *childname, inode_index_t *child_idx);
static fs_retcode_t followPath(filesystem_t *fs, inode_t *start, char **tokens, size_t count, inode_t **dir_out);
static void encodeInode(inode_index_t i, byte *buffer);
static inode_index_t decodeInode(const byte *buffer);
static byte *readDir(filesystem_t *fs, inode_t *dirnode, size_t *e_read);
static fs_retcode_t writeDir(filesystem_t *fs, inode_t *dirnode, const byte *entries, size_t count);
static int tombIndex(const byte *e_arr, size_t e_read);
static inode_index_t childIndex(filesystem_t *fs, inode_t *dirnode, const char *childname);
static size_t dirCap(size_t count);
static void getName(inode_t *inode, char *name);
static void printTree(filesystem_t *fs, inode_t *node, int depth);
// ----------------------- UTILITY FUNCTION ----------------------- //
static size_t tokenize(char *buffer, char *tokens[], size_t depth_max){
    size_t token_count = 0;
    char *p = NULL;
    char *token = strtok_r(buffer, "/", &p);
    while(token && token_count < depth_max){
        tokens[token_count++] = token;
        token = strtok_r(NULL, "/", &p);
    }
    return token_count;
}

static int findChild(filesystem_t *fs, inode_t *dirnode, const char *childname, inode_index_t *child_idx){
    size_t dir_size = dirnode -> internal.file_size;
    if(dirnode -> internal.file_type != DIRECTORY){
        return 0;
    }
    if(dir_size < DIRECTORY_ENTRY_SIZE){
        return 0;
    }
    void *dirbuffer = malloc(dir_size);
    if(!dirbuffer){
        return 0;
    }

    size_t read = 0;
    inode_read_data(fs, dirnode, 0, dirbuffer, dir_size, &read);
    size_t entry_count = read / DIRECTORY_ENTRY_SIZE;
    for(size_t i = 0; i < entry_count; i++){
        unsigned char *ep = (unsigned char*)dirbuffer + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = ep[0] | ((inode_index_t)ep[1] << 8);
        if(index == 0){
            continue;
        }

        char name[MAX_FILE_NAME_LEN + 1];
        memset(name, 0, sizeof(name));
        memcpy(name, ep + sizeof(inode_index_t), MAX_FILE_NAME_LEN);
        if(strncmp(name, childname, MAX_FILE_NAME_LEN) == 0){
            *child_idx = index;
            free(dirbuffer);
            return 1;
        }
    }
    free(dirbuffer);
    return 0;
}

static fs_retcode_t followPath(filesystem_t *fs, inode_t *start, char **tokens, size_t count, inode_t **dir_out){
    if(!fs || !start || !dir_out){
        return INVALID_INPUT;
    }

    if(count == 0){
        *dir_out = start;
        return SUCCESS;
    }

    inode_t *current = start;
    size_t begin = 0;
    if(strcmp(tokens[0], "root") == 0){
        current = &fs->inodes[0];
        begin = 1;
        if(count == 1){
            *dir_out = current;
            return SUCCESS;
        }
    }

    for(size_t i = begin; i < count; i++){
        inode_index_t child_idx = 0;
        int found = findChild(fs, current, tokens[i], &child_idx);
        if(!found){
            return NOT_FOUND;
        }
        inode_t *child = &fs->inodes[child_idx];
        if(child->internal.file_type != DIRECTORY){
            return NOT_FOUND;
        }
        current = child;
    }
    *dir_out = current;
    return SUCCESS;
}
static fs_retcode_t followPathDir(filesystem_t *fs, inode_t *start, char **tokens, size_t count, inode_t **dir_out){
    if(!fs || !start || !dir_out){
        return INVALID_INPUT;
    }
    if(count == 0){
        *dir_out = start;
        return SUCCESS;
    }

    inode_t *current = start;
    size_t begin_index = 0;
    if(strcmp(tokens[0], "root") == 0){
        current = &fs->inodes[0];
        begin_index = 1;
        if(count == 1){
            *dir_out = current;
            return SUCCESS;
        }
    }

    for(size_t i = begin_index; i < count; i++){
        inode_index_t child_idx = 0;
        int found = findChild(fs, current, tokens[i], &child_idx);
        if(!found){
            return NOT_FOUND;
        }
        inode_t *child = &fs->inodes[child_idx];
        if(child->internal.file_type != DIRECTORY){
            return NOT_FOUND;
        }
        current = child;
    }
    *dir_out = current;
    return SUCCESS;
}

static void encodeInode(inode_index_t i, byte *buffer){
    buffer[0] = (byte)(i & 0xFF);
    buffer[1] = (byte)((i >> 8) & 0xFF);
}

static inode_index_t decodeInode(const byte *buffer){
    inode_index_t low = buffer[0];
    inode_index_t high = buffer[1];
    return (inode_index_t)((high << 8) | low);
}

static byte *readDir(filesystem_t *fs, inode_t *dirnode, size_t *e_read){
    size_t dir_size = dirnode -> internal.file_size;
    *e_read = 0;
    if(dir_size == 0){
        return NULL;
    }

    byte *buffer= malloc(dir_size);
    if(!buffer){
        return NULL;
    }
    size_t read = 0;
    inode_read_data(fs, dirnode, 0, buffer, dir_size, &read);

    *e_read = read / DIRECTORY_ENTRY_SIZE;
    return buffer;
}

static fs_retcode_t writeDir(filesystem_t *fs, inode_t *dirnode, const byte *entries, size_t count){
    size_t new_size = count * DIRECTORY_ENTRY_SIZE;
    fs_retcode_t retcode = inode_shrink_data(fs, dirnode, 0);
    if(retcode  != SUCCESS){
        return retcode;
    }

    retcode = inode_write_data(fs, dirnode, (void *)entries, new_size);
    return retcode;
}

static int tombIndex(const byte *e_arr, size_t e_read){
    for(size_t i = 0; i < e_read; i++){
        const byte *e = e_arr + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t idx = decodeInode(e);
        if (idx == 0){
            return (int)i;
        }
    }
    return -1;
}

static inode_index_t childIndex(filesystem_t *fs, inode_t *dirnode, const char *childname){
    size_t e_read = 0;
    byte *dirbuffer = readDir(fs, dirnode, &e_read);
    if(!dirbuffer){
        return 0;
    }

    inode_index_t match = 0;
    for(size_t i = 0; i < e_read; i++){
        byte *p = dirbuffer + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(p);
        if(index == 0){
            continue;
        }
        char name[MAX_FILE_NAME_LEN + 1];
        memset(name,0,sizeof(name));
        memcpy(name,p + 2,MAX_FILE_NAME_LEN);

        if(strncmp(name,childname,MAX_FILE_NAME_LEN) == 0){
            match = index;
            break;
        }
    }
    free(dirbuffer);
    return match;
}

static size_t dirCap(size_t count){
    return count * DIRECTORY_ENTRIES_PER_DATABLOCK; 
}

static void getName(inode_t *inode, char *name){
    size_t i = 0;
    for (; i < MAX_FILE_NAME_LEN; i++) {
        name[i] = inode->internal.file_name[i];
        if (!name[i]) break;
    }
    name[MAX_FILE_NAME_LEN] = '\0';
}

static void printTree(filesystem_t *fs, inode_t *node, int depth){
    char iname[MAX_FILE_NAME_LEN+1];
    getName(node, iname);

    for (int i = 0; i < depth * 3; i++) {
        putchar(' ');
    }
    puts(iname);

    if(node->internal.file_type == DIRECTORY) {
        size_t e_read=0;
        byte *dbuf = readDir(fs, node, &e_read);
        if(!dbuf){
            return;
        }
        
        for(size_t i = 0; i < e_read; i++){
            byte *e = dbuf + i * DIRECTORY_ENTRY_SIZE;
            inode_index_t idx = decodeInode(e);
            if(idx == 0){
                continue; 
            }
            char nm[MAX_FILE_NAME_LEN+1];
            memset(nm,0,sizeof(nm));
            memcpy(nm,e + 2,MAX_FILE_NAME_LEN);
            
            if(strcmp(nm,".") == 0 || strcmp(nm,"..") == 0){
                continue;
            }
            inode_t *child = &fs->inodes[idx];
            printTree(fs, child, depth + 1);
        }
        free(dbuf);
    }
}




// ----------------------- CORE FUNCTION ----------------------- //
//part 3
int new_file(terminal_context_t *context, char *path, permission_t perms)
{
    if(!context || !path){
        return 0;
    }

    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    if(token_count == 0){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(buffer);
        return -1;
    }

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t ret = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(ret != SUCCESS){
            REPORT_RETCODE(DIR_NOT_FOUND);
            free(buffer);
            return -1;
        }
    } 
    else {
        parent = context->working_directory;
    }
    const char *last = tokens[token_count - 1];
    inode_index_t dupe = childIndex(context->fs, parent, last);
    if(dupe != 0){
        REPORT_RETCODE(FILE_EXIST);
        free(buffer);
        return -1;
    }
    size_t parent_size = parent->internal.file_size;
    size_t blocks = parent_size / DIRECTORY_ENTRY_SIZE;
    size_t e_read = 0;
    byte *data = readDir(context->fs, parent, &e_read);
    int tomb_index = tombIndex(data, e_read);
    if(tomb_index < 0){
        size_t curr_count = (parent_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE;
        size_t capacity = dirCap(curr_count);
        if(blocks >= capacity){
            if(available_dblocks(context->fs) < 1){
                REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
                free(data);
                free(buffer);
                return -1;
            }
        }
    }
    inode_index_t new_i = 0;
    fs_retcode_t retcode = claim_available_inode(context->fs, &new_i);
    if(retcode != SUCCESS){
        REPORT_RETCODE(retcode);
        free(data);
        free(buffer);
        return -1;
    }
    inode_t *new_node = &context->fs->inodes[new_i];
    new_node->internal.file_type = DATA_FILE;
    new_node->internal.file_perms = perms;
    new_node->internal.file_size = 0;
    memset(new_node->internal.direct_data, 0, sizeof(new_node->internal.direct_data));
    new_node->internal.indirect_dblock = 0;
    memset(new_node->internal.file_name, 0, MAX_FILE_NAME_LEN);
    strncpy(new_node->internal.file_name, last, MAX_FILE_NAME_LEN);
    byte entry[DIRECTORY_ENTRY_SIZE];
    memset(entry, 0, DIRECTORY_ENTRY_SIZE);
    encodeInode(new_i, entry);
    if(strlen(last) < MAX_FILE_NAME_LEN){
        memcpy(entry + 2, last, strlen(last));
    } 
    else{
        memcpy(entry + 2, last, MAX_FILE_NAME_LEN);
    }

    if(tomb_index >= 0){
        memcpy(data + tomb_index * DIRECTORY_ENTRY_SIZE, entry, DIRECTORY_ENTRY_SIZE);
    } 
    else{
        data = realloc(data, (e_read + 1) * DIRECTORY_ENTRY_SIZE);
        memcpy(data + e_read * DIRECTORY_ENTRY_SIZE, entry, DIRECTORY_ENTRY_SIZE);
        e_read++;
    }
    retcode = writeDir(context->fs, parent, data, e_read);
    free(data);
    free(buffer);
    if(retcode != SUCCESS){
        release_inode(context->fs, new_node);
        REPORT_RETCODE(retcode);
        return -1;
    }
    return 0;
}

int new_directory(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }

    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    if(token_count == 0){
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }

    fs_retcode_t retcode;
    inode_t *parent = NULL;
    if(token_count > 1){
        retcode = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(retcode != SUCCESS){
            free(buffer);
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
    } 
    else{
        parent = context->working_directory;
    }
    const char *last = tokens[token_count - 1];
    inode_index_t dupe = childIndex(context->fs, parent, last);
    if(dupe != 0){
        REPORT_RETCODE(DIRECTORY_EXIST);
        free(buffer);
        return -1;
    }
    size_t e_read = 0;
    byte *dirbuffer = readDir(context->fs, parent, &e_read);
    int tomb_index = tombIndex(dirbuffer, e_read);
    if(tomb_index < 0){
        size_t blocks = parent->internal.file_size / DIRECTORY_ENTRY_SIZE;
        size_t block_count = (parent->internal.file_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE;
        size_t capacity = dirCap(block_count);
        if(blocks >= capacity){
            if(available_dblocks(context->fs) < 1){
                REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
                free(dirbuffer);
                free(buffer);
                return -1;
            }
        }
    }
    if(available_dblocks(context->fs) < 1){
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        free(dirbuffer);
        free(buffer);
        return -1;
    }
    inode_index_t new_i;
    retcode = claim_available_inode(context->fs, &new_i);
    if(retcode != SUCCESS){
        REPORT_RETCODE(retcode);
        free(dirbuffer);
        free(buffer);
        return -1;
    }
    inode_t *new_node = &context->fs->inodes[new_i];
    new_node->internal.file_type = DIRECTORY;
    new_node->internal.file_perms = 0;
    new_node->internal.file_size = 0;
    memset(new_node->internal.direct_data, 0, sizeof(new_node->internal.direct_data));
    new_node->internal.indirect_dblock = 0;
    memset(new_node->internal.file_name, 0, MAX_FILE_NAME_LEN);
    strncpy(new_node->internal.file_name, last, MAX_FILE_NAME_LEN);
    inode_index_t parent_i = (inode_index_t)(parent - context->fs->inodes);
    byte node_entries[2 * DIRECTORY_ENTRY_SIZE];
    memset(node_entries, 0, sizeof(node_entries));
    encodeInode(new_i, &node_entries[0]);
    node_entries[2] = '.';
    encodeInode(parent_i, &node_entries[DIRECTORY_ENTRY_SIZE]);
    node_entries[DIRECTORY_ENTRY_SIZE + 2] = '.';
    node_entries[DIRECTORY_ENTRY_SIZE + 3] = '.';
    retcode = inode_write_data(context->fs, new_node, node_entries, 2 * DIRECTORY_ENTRY_SIZE);
    if(retcode != SUCCESS){
        release_inode(context->fs, new_node);
        free(dirbuffer);
        free(buffer);
        REPORT_RETCODE(retcode);
        return -1;
    }
    byte entry[DIRECTORY_ENTRY_SIZE];
    memset(entry, 0, DIRECTORY_ENTRY_SIZE);
    encodeInode(new_i, entry);
    if(strlen(last) < MAX_FILE_NAME_LEN){
        memcpy(entry + 2, last, strlen(last));
    } 
    else{
        memcpy(entry + 2, last, MAX_FILE_NAME_LEN);
    }
    
    if(tomb_index >= 0){
        memcpy(dirbuffer + tomb_index * DIRECTORY_ENTRY_SIZE, entry, DIRECTORY_ENTRY_SIZE);
    } 
    else{
        dirbuffer = realloc(dirbuffer, (e_read + 1) * DIRECTORY_ENTRY_SIZE);
        memcpy(dirbuffer + e_read * DIRECTORY_ENTRY_SIZE, entry, DIRECTORY_ENTRY_SIZE);
        e_read++;
    }
    retcode = writeDir(context->fs, parent, dirbuffer, e_read);
    free(dirbuffer);
    free(buffer);
    if(retcode != SUCCESS){
        inode_release_data(context->fs, new_node);
        release_inode(context->fs, new_node);
        REPORT_RETCODE(retcode);
        return -1;
    }
    return 0;

}

int remove_file(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }
    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }

    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    if(token_count == 0){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(buffer);
        return -1;
    }

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t ret = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(ret != SUCCESS){
            free(buffer);
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
    } 
    else{
        parent = context->working_directory;
    }
    const char *last = tokens[token_count - 1];
    inode_index_t child_idx = childIndex(context->fs, parent, last);
    if(child_idx == 0){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(buffer);
        return -1;
    }
    inode_t *child = &context->fs->inodes[child_idx];
    if(child->internal.file_type != DATA_FILE){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(buffer);
        return -1;
    }
    size_t e_read = 0;
    byte *dirbuffer = readDir(context->fs, parent, &e_read);
    if(!dirbuffer){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(buffer);
        return -1;
    }
    int to_tomb = -1;
    for(size_t i = 0; i < e_read; i++){
        byte *ent = dirbuffer + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(ent);
        if(index == child_idx){
            to_tomb = (int)i;
            break;
        }
    }
    if(to_tomb < 0){
        free(dirbuffer);
        free(buffer);
        REPORT_RETCODE(FILE_NOT_FOUND);
        return -1;
    }
    memset(dirbuffer + to_tomb * DIRECTORY_ENTRY_SIZE, 0, DIRECTORY_ENTRY_SIZE);
    fs_retcode_t retcode = writeDir(context->fs, parent, dirbuffer, e_read);
    if(retcode != SUCCESS){
        free(dirbuffer);
        free(buffer);
        REPORT_RETCODE(retcode);
        return -1;
    }
    while(e_read > 0){
        byte *remove_tombs = dirbuffer + (e_read - 1) * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(remove_tombs);
        if(index != 0){
            break;
        }
        e_read--;
    }
    retcode = writeDir(context->fs, parent, dirbuffer, e_read);
    free(dirbuffer);
    inode_release_data(context->fs, child);
    release_inode(context->fs, child);
    free(buffer);
    if(retcode != SUCCESS){
        REPORT_RETCODE(retcode);
        return -1;
    }
    return 0;
}

// we can only delete a directory if it is empty!! or cwd
int remove_directory(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }

    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    if(token_count == 0){
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t ret = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(ret != SUCCESS){
            free(buffer);
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
    } 
    else{
        parent = context->working_directory;
    }
    const char *last = tokens[token_count - 1];
    if(strcmp(last, ".") == 0 || strcmp(last, "..") == 0){
        REPORT_RETCODE(INVALID_FILENAME);
        free(buffer);
        return -1;
    }
    inode_index_t child_idx = childIndex(context->fs, parent, last);
    if(child_idx == 0){
        REPORT_RETCODE(DIR_NOT_FOUND);
        free(buffer);
        return -1;
    }
    inode_t *child = &context->fs->inodes[child_idx];
    if(child->internal.file_type != DIRECTORY){
        REPORT_RETCODE(DIR_NOT_FOUND);
        free(buffer);
        return -1;
    }
    inode_t *cwd = context->working_directory;
    if(child == cwd){
        REPORT_RETCODE(ATTEMPT_DELETE_CWD);
        free(buffer);
        return -1;
    }
    size_t dir_content = 0;
    byte *data = readDir(context->fs, child, &dir_content);
    int is_empty = 1;
    for(size_t i = 0; i < dir_content; i++){
        byte *ent = data + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(ent);
        if(index == 0){
            continue;
        }
        char name[MAX_FILE_NAME_LEN + 1];
        memset(name,0,sizeof(name));
        memcpy(name, ent + 2, MAX_FILE_NAME_LEN);
        if(strcmp(name,".") == 0 || strcmp(name,"..") == 0){
        
        }
        else{
            is_empty = 0;
            break;
        }
    }
    if(!is_empty){
        free(data);
        free(buffer);
        REPORT_RETCODE(DIR_NOT_EMPTY);
        return -1;
    }
    free(data);
    size_t parent_enum = 0;
    byte *pbuffer = readDir(context->fs, parent, &parent_enum);
    if(!pbuffer){
        REPORT_RETCODE(DIR_NOT_FOUND);
        free(buffer);
        return -1;
    }
    int sub_target = -1;
    for(size_t i = 0; i < parent_enum; i++){
        byte *ent = pbuffer + i * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(ent);
        if(index == child_idx){
            sub_target = (int)i;
            break;
        }
    }
    if(sub_target < 0){
        free(pbuffer);
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }
    memset(pbuffer + sub_target * DIRECTORY_ENTRY_SIZE, 0, DIRECTORY_ENTRY_SIZE);
    fs_retcode_t retcode = writeDir(context->fs, parent, pbuffer, parent_enum);
    if(retcode != SUCCESS){
        free(pbuffer);
        free(buffer);
        REPORT_RETCODE(retcode);
        return -1;
    }
    while(parent_enum > 0){
        byte *remove_tombs = pbuffer + (parent_enum - 1) * DIRECTORY_ENTRY_SIZE;
        inode_index_t index = decodeInode(remove_tombs);
        if(index != 0){
            break;
        }
        parent_enum--;
    }


    retcode = writeDir(context->fs, parent, pbuffer, parent_enum);
    free(pbuffer);
    inode_release_data(context->fs, child);
    release_inode(context->fs, child);
    free(buffer);
    if(retcode != SUCCESS){
        REPORT_RETCODE(retcode);
        return -1;
    }
    return 0;

}

int change_directory(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }

    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    if(token_count == 0){
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t ret = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(ret != SUCCESS){
            free(buffer);
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
    } 
    else{
        parent = context->working_directory;
    }
    const char *last = tokens[token_count - 1];
    inode_index_t child_idx = childIndex(context->fs, parent, last);
    if(!child_idx){
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }
    inode_t *child = &context->fs->inodes[child_idx];
    if(child->internal.file_type != DIRECTORY){
        free(buffer);
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }
    context->working_directory = child;
    free(buffer);
    return 0;
}

int list(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }
    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t retcode = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(retcode != SUCCESS){
            REPORT_RETCODE(DIR_NOT_FOUND);
            free(buffer);
            return -1;
        }
    } 
    else{
        parent = context->working_directory;
    }

    inode_t *dis_node = NULL;
    if(token_count == 0){
        dis_node = parent;
    } 
    else{
        const char *final = tokens[token_count - 1];
        inode_index_t child_idx = childIndex(context->fs, parent, final);
        if(child_idx == 0){
            REPORT_RETCODE(NOT_FOUND);
            free(buffer);
            return -1;
        }
        dis_node = &context->fs->inodes[child_idx];
    }
    free(buffer);

    if(dis_node->internal.file_type == DATA_FILE){
        char line[256];
        char indicate_type = 'f';
        char indicate_readable = (dis_node->internal.file_perms & FS_READ) ? 'r' : '-';
        char indicate_writable = (dis_node->internal.file_perms & FS_WRITE) ? 'w' : '-';
        char indicate_exec = (dis_node->internal.file_perms & FS_EXECUTE) ? 'x' : '-';
        sprintf(line, "%c%c%c%c\t%lu\t%s", indicate_type, indicate_readable, indicate_writable, indicate_exec, (unsigned long)dis_node->internal.file_size, dis_node->internal.file_name);
        puts(line);
    }
    else{
        size_t e_read = 0;
        byte *buf = readDir(context->fs, dis_node, &e_read);
        if(!buf){
            return 0;
        }
        for(size_t i = 0; i < e_read; i++){
            byte *ent = buf + i * DIRECTORY_ENTRY_SIZE;
            inode_index_t idx = decodeInode(ent);
            if(idx == 0){
                continue;
            }

            char namebuf[MAX_FILE_NAME_LEN + 1];
            memset(namebuf, 0, sizeof(namebuf));
            memcpy(namebuf, ent + 2, MAX_FILE_NAME_LEN);
            inode_t *child = &context->fs->inodes[idx];
            char indicate_type = 'E'; // E = error?
            if(child->internal.file_type == DATA_FILE){
                indicate_type = 'f';
            }
            else if(child->internal.file_type == DIRECTORY){
                indicate_type = 'd';
            }

            char indicate_readable = (child->internal.file_perms & FS_READ) ? 'r' : '-';
            char indicate_writable = (child->internal.file_perms & FS_WRITE) ? 'w' : '-';
            char indicate_exec = (child->internal.file_perms & FS_EXECUTE) ? 'x' : '-';
            printf("%c%c%c%c\t%lu\t%s", indicate_type, indicate_readable, indicate_writable, indicate_exec, (unsigned long)child->internal.file_size, namebuf);
            if(strcmp(namebuf, ".") == 0 || strcmp(namebuf, "..") == 0){
                char childname[MAX_FILE_NAME_LEN + 1];
                getName(child, childname);
                printf(" -> %s", childname);
            }
            printf("\n");
        }
        free(buf);
    }
    return 0;
}

char *get_path_string(terminal_context_t *context)
{
    if (!context) {
        char *empty = malloc(1);
        empty[0] = '\0';
        return empty;
    }
    inode_t *cwd = context->working_directory;
    filesystem_t *fs = context->fs;
    if (cwd == &fs->inodes[0]) {
        return strdup("root");
    }

    char *names[200];
    size_t depth = 0;
    inode_t *current = cwd;
    while (1) {
        if (current == &fs->inodes[0]) {
            names[depth++] = strdup("root");
            break;
        }

        char curname[MAX_FILE_NAME_LEN + 1];
        getName(current, curname);
        names[depth++] = strdup(curname);
        
        size_t e_read = 0;
        byte *dbuf = readDir(fs, current, &e_read);
        if (!dbuf){
         break;
        }
        inode_index_t parent_idx = 0;
        for (size_t i = 0; i < e_read; i++) {
            byte *ent = dbuf + i * DIRECTORY_ENTRY_SIZE;
            inode_index_t idx = decodeInode(ent);
            if (idx != 0) {
                char nm[MAX_FILE_NAME_LEN + 1];
                memset(nm, 0, sizeof(nm));
                memcpy(nm, ent + 2, MAX_FILE_NAME_LEN);
                if (strcmp(nm, "..") == 0) {
                    parent_idx = idx;
                    break;
                }
            }
        }
        free(dbuf);
        if (!parent_idx || parent_idx == (inode_index_t)(current - fs->inodes)) {
             break;
        }
        current = &fs->inodes[parent_idx];
        if (depth >= 200) break;
    }

    size_t total_len = 0;
    for (size_t i = 0; i < depth; i++) {
        total_len += strlen(names[i]) + 1;
    }
    char *final_path = malloc(total_len + 1);
    if (!final_path) {
        for (size_t i = 0; i < depth; i++) {
            free(names[i]);
        }
        char *e = malloc(1);
        e[0] = '\0';
        return e;
    }
    final_path[0] = '\0';

    for (size_t i = 0; i < depth; i++) {
        size_t idx = depth - 1 - i;
        strcat(final_path, names[idx]);
        if (i < depth - 1) {
            strcat(final_path, "/");
        }
    }

    for (size_t i = 0; i < depth; i++) {
        free(names[i]);
    }
    return final_path;
}

int tree(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return 0;
    }

    char *buffer = strdup(path);
    if(!buffer){
        return -1;
    }
    char *tokens[200];
    size_t token_count = tokenize(buffer, tokens, 200);
    inode_t *parent=NULL;
    if(token_count > 1){
        fs_retcode_t retcode = followPath(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(retcode != SUCCESS){
            REPORT_RETCODE(DIR_NOT_FOUND);
            free(buffer);
            return -1;
        }
    } 
    else {
        parent = context->working_directory;
    }

    inode_t *dis_node = NULL;
    if(token_count == 0){
        dis_node = parent;
    } 
    else{
        const char *final = tokens[token_count - 1];
        inode_index_t child_idx = childIndex(context->fs, parent, final);
        if(child_idx == 0){
            REPORT_RETCODE(NOT_FOUND);
            free(buffer);
            return -1;
        }
        dis_node = &context->fs->inodes[child_idx];
    }
    free(buffer);

    if(dis_node->internal.file_type != DIRECTORY){
        puts(dis_node->internal.file_name);
        return 0;
    }

    printTree(context->fs, dis_node, 0);
    return 0;
}

// ----------------------- CORE FUNCTION ----------------------- //
//Part 2
void new_terminal(filesystem_t *fs, terminal_context_t *term)
{
    
    //check if inputs are valid
    if(!fs || !term){
        return;
    }
    //assign file system and root inode.
    term -> fs = fs;
    term -> working_directory = &fs -> inodes[0];
}

fs_file_t fs_open(terminal_context_t *context, char *path)
{
    if(!context || !path){
        return NULL;
    }
    char *path_name = strdup(path);
    if(!path_name){
        return NULL;
    }

    char *tokens[200];
    size_t token_count = tokenize(path_name, tokens, 200);
    if(token_count == 0){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(path_name);
        return NULL;
    }

    inode_t *parent = NULL;
    if(token_count > 1){
        fs_retcode_t ret = followPathDir(context->fs, context->working_directory, tokens, token_count - 1, &parent);
        if(ret != SUCCESS){
            REPORT_RETCODE(DIR_NOT_FOUND);
            free(path_name);
            return NULL;
        }
    } 
    else{
        parent = context->working_directory;
    }

    const char *final_token = tokens[token_count - 1];
    inode_index_t child_idx = 0;
    int found = findChild(context->fs, parent, final_token, &child_idx);
    if(!found){
        REPORT_RETCODE(FILE_NOT_FOUND);
        free(path_name);
        return NULL;
    }

    inode_t *child = &context->fs->inodes[child_idx];
    if(child->internal.file_type != DATA_FILE){
        REPORT_RETCODE(INVALID_FILE_TYPE);
        free(path_name);
        return NULL;
    }

    fs_file_t file = malloc(sizeof(*file));
    if(!file){
        free(path_name);
        return NULL;
    }
    file->fs = context->fs;
    file->inode = child;
    file->offset = 0;

    free(path_name);
    return file;
}

void fs_close(fs_file_t file)
{
    if(!file){
        return;
    }
    
    free(file);
}

size_t fs_read(fs_file_t file, void *buffer, size_t n)
{
    if(!file || !buffer){
        return 0;
    }

    size_t read = 0;
    fs_retcode_t retcode = inode_read_data(file -> fs, file -> inode, file -> offset, buffer, n, &read);
    (void)retcode;
    file -> offset += read;
    return read;

}

size_t fs_write(fs_file_t file, void *buffer, size_t n)
{
    if(!file || !buffer || n ==0){
        return 0;
    }

    fs_retcode_t retcode = inode_modify_data(file -> fs, file -> inode, file -> offset, buffer, n);
    if(retcode  != SUCCESS){
        REPORT_RETCODE(retcode ); 
        return 0;
    }
    file -> offset += n;
    return n;
}

int fs_seek(fs_file_t file, seek_mode_t seek_mode, int offset)
{
    if(!file){
        return -1;
    }

    size_t file_size = file -> inode -> internal.file_size;
    long off = 0;
    switch(seek_mode){
        case FS_SEEK_START: 
        off = offset;
        break;
        
        case FS_SEEK_CURRENT: 
        off = (long)file -> offset + offset;
        break;

        case FS_SEEK_END:
        off = (long)file_size + offset;
        break;

        default: return -1;
    }

    if(off < 0){
        return -1;
    }
    if((size_t)off > file_size){
        off = file_size;
    }
    file -> offset = (size_t)off;
    return 0;
}

