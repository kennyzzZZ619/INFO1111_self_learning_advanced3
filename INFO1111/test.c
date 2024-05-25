#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define SHA256K 64
#define SHA256_HEXLEN 64
#define SHA256_CHUNK_SZ 64
#define SHA256_INT_SZ 8
#define rotate_r(val,bits) (val >> bits | val << (32 - bits))

struct sha256_compute_data {
    uint64_t data_size;
    uint32_t hcomps[SHA256_INT_SZ];
    uint8_t last_chunk[SHA256_CHUNK_SZ];
    uint8_t chunk_size;
};

struct merkle_tree_node {
    struct merkle_tree_node *left;
    struct merkle_tree_node *right;
    int is_leaf;
    char expected_hash[SHA256_HEXLEN];
    char computed_hash[SHA256_HEXLEN];
};
typedef struct{
    char* hash;
    uint32_t offset;
    uint32_t size;
}Chunks;

typedef struct{
    char *ident;
    char *filename;
    uint32_t size;
    uint32_t nhashes;
    char **hashes;
    uint32_t nchunks;
    Chunks* chunks;
}bpkg_obj;

void sha256_compute_data_init(struct sha256_compute_data *data);
void sha256_calculate_chunk(struct sha256_compute_data *data, uint8_t chunk[SHA256_CHUNK_SZ]);
void sha256_update(struct sha256_compute_data *data, void *bytes, uint32_t size);
void sha256_finalize(struct sha256_compute_data *data, uint8_t hash[SHA256_INT_SZ]);
void sha256_output_hex(struct sha256_compute_data *data, char hexbuf[SHA256_HEXLEN]);


bpkg_obj *bpkg_load(const char *path);
struct merkle_tree_node *create_node(const char *expected_hash, const char *computed_hash, int is_leaf);
void compute_hash(struct merkle_tree_node *node);
struct merkle_tree_node *build_merkle_tree(bpkg_obj *obj, char **computed_hashes);
void free_tree(struct merkle_tree_node *node);
void get_sha256_hash(char *input, char *output);
void clear_rest_line(FILE *file, char buffer[]);
void print_merkle_tree(struct merkle_tree_node* node, int level);
char** read_computed_hash(char* data_filename, bpkg_obj* obj);

static const uint32_t k[SHA256K] = {
    0x428a2f98, 0x71374491, 
    0xb5c0fbcf, 0xe9b5dba5, 
    0x3956c25b, 0x59f111f1, 
    0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 
    0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 
    0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 
    0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 
    0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 
    0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 
    0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 
    0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 
    0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 
    0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 
    0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 
    0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 
    0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 
    0xbef9a3f7, 0xc67178f2
};
//static const uint32_t k[SHA256K] = { /* initialize with SHA-256 constants */ };

void sha256_compute_data_init(struct sha256_compute_data *data) {
    data->hcomps[0] = 0x6a09e667;
    data->hcomps[1] = 0xbb67ae85;
    data->hcomps[2] = 0x3c6ef372;
    data->hcomps[3] = 0xa54ff53a;
    data->hcomps[4] = 0x510e527f;
    data->hcomps[5] = 0x9b05688c;
    data->hcomps[6] = 0x1f83d9ab;
    data->hcomps[7] = 0x5be0cd19;

    data->data_size = 0;
    data->chunk_size = 0;
}

void sha256_calculate_chunk(struct sha256_compute_data *data, 
		uint8_t chunk[SHA256_CHUNK_SZ]) {
	uint32_t w[SHA256_CHUNK_SZ];
	uint32_t tv[SHA256_INT_SZ];

    //
	for(uint32_t i = 0; i < 16; i++) {
		w[i] = (uint32_t) chunk[0] << 24 
			| (uint32_t) chunk[1] << 16 
			| (uint32_t) chunk[2] << 8 
			| (uint32_t) chunk[3];

		chunk += 4;
	}

    //
	for(uint32_t i = 16; i < 64; i++) {
		
		uint32_t s0 = rotate_r(w[i-15], 7) 
			    ^ rotate_r(w[i-15], 18) 
			    ^ (w[i-15] >> 3);
		
		uint32_t s1 = rotate_r(w[i-2], 17) 
			    ^ rotate_r(w[i-2], 19) 
			    ^ (w[i-2] >> 10);

		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	for(uint32_t i = 0; i < SHA256_INT_SZ; i++) {
		tv[i] = data->hcomps[i];
	}

	for(uint32_t i = 0; i < SHA256_CHUNK_SZ; i++) {
		uint32_t S1 = rotate_r(tv[4], 6) 
			    ^ rotate_r(tv[4], 11) 
			    ^ rotate_r(tv[4], 25);

		uint32_t ch = (tv[4] & tv[5]) 
			    ^ (~tv[4] & tv[6]);
		
		uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
		
		uint32_t S0 = rotate_r(tv[0], 2) 
			    ^ rotate_r(tv[0], 13) 
			    ^ rotate_r(tv[0], 22);
		
		uint32_t maj = (tv[0] & tv[1]) 
			     ^ (tv[0] & tv[2]) 
			     ^ (tv[1] & tv[2]);
		
		uint32_t temp2 = S0 + maj;
		
		tv[7] = tv[6];
		tv[6] = tv[5];
		tv[5] = tv[4];
		tv[4] = tv[3] + temp1;
		tv[3] = tv[2];
		tv[2] = tv[1];
		tv[1] = tv[0];
		tv[0] = temp1 + temp2;
	}

	for(uint32_t i = 0; i < SHA256_INT_SZ; i++) {
		data->hcomps[i] += tv[i];
	}
}

void sha256_update(struct sha256_compute_data *data, void *bytes, uint32_t size) {
    uint8_t *ptr = (uint8_t *)bytes;
    data->data_size += size;

    if (size + data->chunk_size >= 64) {
        uint8_t tmp_chunk[64];
        memcpy(tmp_chunk, data->last_chunk, data->chunk_size);
        memcpy(tmp_chunk + data->chunk_size, ptr, 64 - data->chunk_size);
        ptr += (64 - data->chunk_size);
        size -= (64 - data->chunk_size);
        data->chunk_size = 0;
        sha256_calculate_chunk(data, tmp_chunk);
    }

    while (size >= 64) {
        sha256_calculate_chunk(data, ptr);
        ptr += 64;
        size -= 64;
    }

    memcpy(data->last_chunk + data->chunk_size, ptr, size);
    data->chunk_size += size;
}

void sha256_finalize(struct sha256_compute_data *data, uint8_t hash[SHA256_INT_SZ]) {
    data->last_chunk[data->chunk_size] = 0x80;
    data->chunk_size++;
    memset(data->last_chunk + data->chunk_size, 0, 64 - data->chunk_size);

    if (data->chunk_size > 56) {
        sha256_calculate_chunk(data, data->last_chunk);
        memset(data->last_chunk, 0, 64);
    }

    uint64_t size = data->data_size * 8;
    for (int32_t i = 8; i > 0; --i) {
        data->last_chunk[55 + i] = size & 255;
        size >>= 8;
    }
    sha256_calculate_chunk(data, data->last_chunk);
}

void sha256_output(struct sha256_compute_data *data, uint8_t *hash) {
    for (uint32_t i = 0; i < 8; i++) {
        hash[i * 4] = (data->hcomps[i] >> 24) & 255;
        hash[i * 4 + 1] = (data->hcomps[i] >> 16) & 255;
        hash[i * 4 + 2] = (data->hcomps[i] >> 8) & 255;
        hash[i * 4 + 3] = data->hcomps[i] & 255;
    }
}

static void bin_to_hex(const void *data, uint32_t len, char *out) {
    static const char *const lut = "0123456789abcdef";
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t c = ((const uint8_t *)data)[i];
        out[i * 2] = lut[c >> 4];
        out[i * 2 + 1] = lut[c & 15];
    }
}

void sha256_output_hex(struct sha256_compute_data *data, char hexbuf[SHA256_HEXLEN]) {
    uint8_t hash[32] = {0};
    sha256_output(data, hash);
    bin_to_hex(hash, 32, hexbuf);
}

void clear_rest_line(FILE *file, char buffer[]) {
    if (strchr(buffer, '\n') == NULL) {
        int c;
        while ((c = fgetc(file)) != '\n' && c != EOF);
    }
}

bpkg_obj *bpkg_load(const char *path) {
    bpkg_obj *obj = malloc(sizeof(bpkg_obj));
    if (obj == NULL) {
        fprintf(stderr, "Memory allocation failed for bpkg_obj\n");
        return NULL;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(obj);
        return NULL;
    }

    char buffer[1025];
    memset(buffer, 0, sizeof(buffer));

    if (!fgets(buffer, sizeof(buffer), file) || buffer[5] != ':') {
        fprintf(stderr, "Failed to read identifier\n");
        fclose(file);
        free(obj);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    obj->ident = strdup(buffer + 6);
    printf("Ident: %s\n", obj->ident);

    clear_rest_line(file, buffer);

    if (!fgets(buffer, sizeof(buffer), file) || buffer[8] != ':') {
        fprintf(stderr, "Failed to read filename\n");
        fclose(file);
        free(obj);
        free(obj->ident);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    obj->filename = strdup(buffer + 9);
    printf("Filename: %s\n", obj->filename);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "size:%u", &obj->size) != 1) {
        fprintf(stderr, "Failed to parse size.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Size: %u\n", obj->size);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "nhashes:%u", &obj->nhashes) != 1) {
        fprintf(stderr, "Failed to parse nhashes.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Nhashes: %u\n", obj->nhashes);

    obj->hashes = (char **)malloc(obj->nhashes * sizeof(char *));
    if (obj->hashes == NULL) {
        fprintf(stderr, "Failed to allocate memory for hashes\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }

    char temp[64];
    fgets(temp, 64, file);
    int actualIndex = 0;
    for (int i = 0; i < obj->nhashes * 2; i++) {
        char *tempstore = (char *)malloc(66);
        if (fgets(tempstore, 66, file) == NULL) {
            free(tempstore);
            break;
        }

        if (tempstore[0] != '\n' && tempstore[0] != '\r' && strlen(tempstore) > 0) {
            if (actualIndex > obj->nhashes) {
                fprintf(stderr, "More non-empty lines than expected\n");
                break;
            }

            obj->hashes[actualIndex] = (char *)malloc(66);
            if (obj->hashes[actualIndex] == NULL) {
                fprintf(stderr, "Failed to allocate memory for hash %d\n", actualIndex);
                free(tempstore);
                break;
            }

            strcpy(obj->hashes[actualIndex], tempstore);
            obj->hashes[actualIndex] = strtok(obj->hashes[actualIndex], "\r\n");
            obj->hashes[actualIndex] = strtok(obj->hashes[actualIndex], "\t");
            printf("%d: %s\n", actualIndex, obj->hashes[actualIndex]);
            actualIndex++;
        }

        free(tempstore);
    }

    if (actualIndex != obj->nhashes) {
        fprintf(stderr, "Mismatch in the number of expected non-empty hashes\n");
    }

    char tempb[65];
    if (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "nchunks:%u", &obj->nchunks) != 1) {
            fprintf(stderr, "Failed to parse nchunks.\n");
            fclose(file);
            free(obj->filename);
            free(obj->ident);
            free(obj);
            return NULL;
        }
        printf("Nchunks: %u\n", obj->nchunks);
    } else {
        fprintf(stderr, "Failed to read line for nchunks.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    fgets(buffer, sizeof(buffer), file);

    char line[256];
    int index = 0;
    unsigned long tempOffset, tempSize;
    obj->chunks = malloc(obj->nchunks * sizeof(Chunks));
    if (obj->chunks == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash\n");
        fclose(file);
        return NULL;
    }
    while (fgets(line, sizeof(line), file) && index < obj->nchunks) {
        char *clean_line = strtok(line, "\n\r");
        clean_line = strtok(clean_line, "\t");
        obj->chunks[index].hash = malloc(65);
        if (obj->chunks[index].hash == NULL) {
            fprintf(stderr, "Failed to allocate memory for hash\n");
            fclose(file);
            return NULL;
        }

        int result = sscanf(clean_line, "%64[^,],%lu,%lu", obj->chunks[index].hash, &tempOffset, &tempSize);
        if (result != 3) {
            printf("DID NOT READ ALL DATA!");
        }
        obj->chunks[index].offset = (uint32_t)tempOffset;
        obj->chunks[index].size = (uint32_t)tempSize;
        obj->chunks[index].hash[strcspn(obj->chunks[index].hash, "\r\n")] = 0;
        index++;
    }

    for (int i = 0; i < obj->nchunks; i++) {
        printf("Chunk %d: Hash = %s, Offset = %u, Size = %u\n", i, obj->chunks[i].hash, obj->chunks[i].offset, obj->chunks[i].size);
    }

    fclose(file);
    return obj;
}


struct merkle_tree_node *create_node(const char *expected_hash, const char *computed_hash, int is_leaf) {
    struct merkle_tree_node *node = malloc(sizeof(struct merkle_tree_node));
    if (!node) {
        fprintf(stderr, "Failed to allocate node.\n");
        return NULL;
    }
    if (expected_hash) {
        strncpy(node->expected_hash, expected_hash, SHA256_HEXLEN);
    } else {
        memset(node->expected_hash, 0, SHA256_HEXLEN);
    }
    if (computed_hash) {
        strncpy(node->computed_hash, computed_hash, SHA256_HEXLEN);
    } else {
        memset(node->computed_hash, 0, SHA256_HEXLEN);
    }
    node->is_leaf = is_leaf;
    node->left = node->right = NULL;
    return node;
}

void compute_hash(struct merkle_tree_node *node) {
    if (node->left && node->right) {
        char combined[SHA256_HEXLEN * 2 + 1];
        snprintf(combined, sizeof(combined), "%s%s", node->left->computed_hash, node->right->computed_hash);
        get_sha256_hash(combined, node->computed_hash);
    }
}


struct merkle_tree_node *build_merkle_tree(bpkg_obj *obj,char **hashes) {
    int n = obj->nchunks; 
    int total_nodes = n * 2 - 1;
    struct merkle_tree_node **nodes = malloc(sizeof(struct merkle_tree_node *) * total_nodes);
    if (!nodes) {
        fprintf(stderr, "Failed to allocate nodes.\n");
        return NULL;
    }

    // Initialize leaf nodes
    for (int i = 0; i < n; i++) {
        nodes[i] = create_node(obj->chunks[i].hash, hashes[i], 1);
        if (!nodes[i]) {
            fprintf(stderr, "Failed to create node.\n");
            for (int j = 0; j < i; j++) free(nodes[j]);
            free(nodes);
            return NULL;
        }
        //printf("%d\n",i);
    }

    int current_level_count = n;
    int next_level_start = n;
    int non_leaf_index = 0;

    // Build the tree from leaf nodes up to the root
    while (current_level_count > 1) {
        int next_level_count = 0;
        for (int i = 0; i < current_level_count; i += 2) {
            if (i + 1 < current_level_count) {
                nodes[next_level_start + next_level_count] = create_node("", "", 0);
                if (!nodes[next_level_start + next_level_count]) {
                    fprintf(stderr, "Failed to create non-leaf node.\n");
                    for (int j = 0; j < next_level_start + next_level_count; j++) free(nodes[j]);
                    free(nodes);
                    return NULL;
                }
                nodes[next_level_start + next_level_count]->left = nodes[i];
                nodes[next_level_start + next_level_count]->right = nodes[i + 1];
                compute_hash(nodes[next_level_start + next_level_count]);
                non_leaf_index++;
                printf("Non-leaf node %d | Computed hash: %s\n", non_leaf_index, nodes[next_level_start + next_level_count]->computed_hash);
                //printf("%d\n",next_level_start + next_level_count);
            } else {
                nodes[next_level_start + next_level_count] = nodes[i];
            }
            next_level_count++;
        }
        current_level_count = next_level_count;
        next_level_start += next_level_count;
    }

    struct merkle_tree_node *root = nodes[next_level_start - 1];
    //free(nodes);
    return root;
}

void free_tree(struct merkle_tree_node *node) {
    if (!node) return;
    free_tree(node->left);
    free_tree(node->right);
    free(node);
}



void get_sha256_hash(char *input, char *output) {
    struct sha256_compute_data data;
    sha256_compute_data_init(&data);
    sha256_update(&data, input, strlen(input));
    sha256_finalize(&data, (uint8_t *)output);
    sha256_output_hex(&data, output);
}

void print_merkle_tree(struct merkle_tree_node *node, int level) {
    if (!node) return;
    for (int i = 0; i < level; i++) {
        printf("  ");
    }
    printf("Level %d | Expected hash: %s | Computed hash: %s | %s\n",
           level, node->expected_hash, node->computed_hash, node->is_leaf ? "leaf" : "non-leaf");
    print_merkle_tree(node->left, level + 1);
    print_merkle_tree(node->right, level + 1);
}

char** read_computed_hash(char* data_filename, bpkg_obj* obj) {
    // Open the file using the full path
    FILE* data_file = fopen(data_filename, "rb");
    if (data_file == NULL) {
        perror("Failed to open file");
        return NULL;
    }
    char** computed_hashes = malloc(obj->nchunks * sizeof(char*));
    if (!computed_hashes) {
        fprintf(stderr, "Failed to allocate memory for hashes");
        fclose(data_file);
        return NULL;
    }

    struct sha256_compute_data cdata;
    for (int i = 0; i < obj->nchunks; i++) {
        if (fseek(data_file, obj->chunks[i].offset, SEEK_SET) != 0) {
            perror("Failed to seek in file");
            for (int j = 0; j < i; ++j) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            return NULL;
        }
        char* data_chunk = malloc(obj->chunks[i].size);
        if (!data_chunk) {
            perror("Failed to allocate memory for data chunk");
            for (int j = 0; j <= i; ++j) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            return NULL;
        }
        size_t read_size = fread(data_chunk, 1, obj->chunks[i].size, data_file);
        if (read_size != obj->chunks[i].size) {
            perror("Failed to read the complete data chunk");
            free(data_chunk);
            for (int j = 0; j <= i; ++j) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            return NULL;
        }
        sha256_compute_data_init(&cdata);
        sha256_update(&cdata, data_chunk, obj->chunks[i].size);
        sha256_finalize(&cdata, (uint8_t*)computed_hashes[i]);
        computed_hashes[i] = malloc((SHA256_HEXLEN + 1) * sizeof(char));
        if (!computed_hashes[i]) {
            perror("Failed to allocate memory for computed hash");
            free(data_chunk);
            for (int j = 0; j <= i; ++j) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            return NULL;
        }
        sha256_output_hex(&cdata, computed_hashes[i]);
        computed_hashes[i][SHA256_HEXLEN] = '\0';
        free(data_chunk);
    }
    fclose(data_file);
    return computed_hashes;
}

int main() {
    char *bpkg_filename = "file1.bpkg";
    char *data_filename = "file1.data";
    bpkg_obj *obj = bpkg_load(bpkg_filename);
    if (!obj) {
        fprintf(stderr, "Failed to load bpkg file.\n");
        return -1;
    }


    char **computed_hashes = malloc(obj->nchunks * sizeof(char *));
    computed_hashes = read_computed_hash(data_filename,obj);
    struct merkle_tree_node *root = build_merkle_tree(obj, computed_hashes);
    if (!root) {
        fprintf(stderr, "Failed to build Merkle tree.\n");
        return -1;
    }

    //for (int i = 0; i < obj->nhashes; i++) {
    //    printf("Expected hash: %s\n", obj->hashes[i]);
    //}
    for(int i=0;i<obj->nchunks;i++){
      printf("computed hash: %s\n",computed_hashes[i]);

    }
    //print_merkle_tree(root,0);
    free_tree(root);
    free(computed_hashes);
    return 0;
}
