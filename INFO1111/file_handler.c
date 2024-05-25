#include <stdio.h>
#include <stdlib.h>

void create_file(const char* filename) {
    FILE *file = fopen(filename, "w"); 
    if (file == NULL) {
        printf("Error opening file for writing.\n");
        return;
    }
    fprintf(file, "Hello, this is a test file.\n");
    fclose(file);
    printf("File created and written successfully.\n");
}

void read_file(const char* filename) {
    char buffer[255];
    FILE *file = fopen(filename, "r"); 
    if (file == NULL) {
        printf("Error opening file for reading.\n");
        return;
    }
    while (fgets(buffer, 255, file) != NULL) {
        printf("%s", buffer);
    }
    fclose(file);
}

void update_file(const char* filename) {
    FILE *file = fopen(filename, "a"); 
    if (file == NULL) {
        printf("Error opening file for appending.\n");
        return;
    }
    fprintf(file, "Appending a new line to the file.\n");
    fclose(file);
    printf("File updated successfully.\n");
}

void delete_file(const char* filename) {
    if (remove(filename) == 0) {
        printf("File deleted successfully.\n");
    } else {
        printf("Error deleting the file.\n");
    }
}

int main() {
    const char* filename = "example.txt";
    
    create_file(filename);
    read_file(filename);
    update_file(filename);
    read_file(filename);
    delete_file(filename);  //<--You can try to remove this line
    
    return 0;
}
