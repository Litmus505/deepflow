#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/simple_java_profiler.socket"
#define BUFFER_SIZE 2048

int main() {
    int server_fd, new_socket;
    struct sockaddr_un address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    
    unlink(SOCKET_PATH);
    
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("Simple Java Profiler Receiver listening on %s...\n", SOCKET_PATH);
    
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    printf("Agent connected!\n");
    
    FILE *map_file = fopen("/tmp/perf-simple.map", "w");
    if (!map_file) {
        perror("fopen failed");
        close(new_socket);
        close(server_fd);
        unlink(SOCKET_PATH);
        exit(EXIT_FAILURE);
    }
    
    while (1) {
        ssize_t valread = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (valread <= 0) {
            break;
        }
        buffer[valread] = '\0';
        printf("Received: %s", buffer);
        
        if (strncmp(buffer, "[Symbol Load]", 13) == 0) {
            char *ptr = buffer + 14;
            fprintf(map_file, "%s", ptr);
            fflush(map_file);
        }
    }
    
    fclose(map_file);
    close(new_socket);
    close(server_fd);
    unlink(SOCKET_PATH);
    
    return 0;
}
