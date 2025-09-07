#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>
#include <microhttpd.h>
#include <libwebsockets.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/wait.h>

#define IPINFO_URL "https://ipinfo.io/json?token=f0733aeae6faa4"
#define PORT 8081
#define WS_REFRESH_INTERVAL 1

typedef struct {
    char type[16];
    char url[256];
    char name[128];
    int status;
} Service;

Service *services = NULL;
int service_count = 0;
char server_location[256] = "Unknown";
time_t last_health_check = 0;
int refresh_time = 15;
char version[16] = "1.0";
pthread_mutex_t health_mutex;

size_t write_callback(void *ptr, size_t size, size_t nmemb, char **data) {
    size_t new_size = size * nmemb;
    *data = realloc(*data, new_size + 1);
    memcpy(*data, ptr, new_size);
    (*data)[new_size] = '\0';
    return new_size;
}

float get_cpu_usage() {
    FILE *fp;
    char line[256];
    unsigned long long prev_idle, prev_total, idle, total;
    
    fp = fopen("/proc/stat", "r");
    if (!fp) return -1;
    fgets(line, sizeof(line), fp);
    fclose(fp);
    
    sscanf(line, "cpu %*u %*u %*u %llu %*u %*u %*u %*u %*u %*u", &prev_idle);
    prev_total = 0;
    for (int i = 0; i < 10; i++) prev_total += strtoull(strtok(i == 0 ? line + 4 : NULL, " "), NULL, 10);
    
    sleep(1);
    
    fp = fopen("/proc/stat", "r");
    if (!fp) return -1;
    fgets(line, sizeof(line), fp);
    fclose(fp);
    
    sscanf(line, "cpu %*u %*u %*u %llu %*u %*u %*u %*u %*u %*u", &idle);
    total = 0;
    for (int i = 0; i < 10; i++) total += strtoull(strtok(i == 0 ? line + 4 : NULL, " "), NULL, 10);
    
    return 100.0 * (1.0 - ((idle - prev_idle) * 1.0 / (total - prev_total)));
}

void get_memory_usage(double *used, double *total) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return;
    
    unsigned long mem_total, mem_available;
    char label[32];
    
    while (fscanf(fp, "%31s %lu kB", label, &mem_total) == 2) {
        if (strcmp(label, "MemTotal:") == 0) *total = mem_total / 1048576.0;
        if (strcmp(label, "MemAvailable:") == 0) {
            mem_available = mem_total;
            *used = (*total) - (mem_available / 1048576.0);
            break;
        }
    }
    fclose(fp);
}

void get_server_location() {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char *response = NULL;
    
    curl_easy_setopt(curl, CURLOPT_URL, IPINFO_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (!response) return;
    
    json_t *root;
    json_error_t error;
    root = json_loads(response, 0, &error);
    free(response);
    if (!root) return;
    
    const char *region = json_string_value(json_object_get(root, "region"));
    const char *country = json_string_value(json_object_get(root, "country"));
    const char *org = json_string_value(json_object_get(root, "org"));
    
    if (region && country && org)
        snprintf(server_location, sizeof(server_location), "%s, %s, %s", region, country, org);
    
    json_decref(root);
}

int check_http_health(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    long response_code = 0;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    }
    
    curl_easy_cleanup(curl);
    return (response_code < 500 && response_code != 0);
}

int check_tcp_health(const char *url) {
    if (strncmp(url, "unix://", 7) == 0) {
        struct sockaddr_un addr;
        int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) return 0;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, url + 7, sizeof(addr.sun_path) - 1);

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sockfd);
            return 0;
        }

        close(sockfd);
        return 1;
    } else {
        struct addrinfo hints, *res;
        int sockfd;
        char host[256], port[16];

        if (sscanf(url, "tcp://%255[^:]:%15s", host, port) != 2) {
            return 0;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host, port, &hints, &res) != 0) return 0;

        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            freeaddrinfo(res);
            return 0;
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
            close(sockfd);
            freeaddrinfo(res);
            return 0;
        }

        close(sockfd);
        freeaddrinfo(res);
        return 1;
    }
}

long get_system_uptime() {
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) return -1;
    
    double uptime;
    fscanf(fp, "%lf", &uptime);
    fclose(fp);
    
    return (long)uptime;
}

void format_uptime(long uptime, char *buffer, size_t buffer_size) {
    long days = uptime / 86400;
    long hours = (uptime % 86400) / 3600;
    long minutes = (uptime % 3600) / 60;
    long seconds = uptime % 60;
    
    snprintf(buffer, buffer_size, "%ld days, %ld hours, %ld minutes, %ld seconds", days, hours, minutes, seconds);
}

json_t *get_logged_in_users() {
    FILE *fp;
    char line[256];
    json_t *users_array = json_array();

    fp = popen("users 2>/dev/null", "r");
    if (!fp) return json_array();

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *token = strtok(line, " \n");
        while (token) {
            json_array_append_new(users_array, json_string(token));
            token = strtok(NULL, " \n");
        }
    }

    pclose(fp);
    return users_array;
}

json_t *get_top_processes() {
    FILE *fp;
    char line[256];
    json_t *processes_array = json_array();

    fp = popen("ps -eo pid,comm,%cpu,%mem,etime --sort=-%cpu | awk 'NR==1 || ($2!=\"ps\" && $2!=\"healthcheck\")' | head -n 6 2>/dev/null", "r");
    if (!fp) return json_array();

    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp) != NULL) {
        char pid[16], comm[64], cpu[16], mem[16], etime[16];
        if (sscanf(line, "%15s %63s %15s %15s %15s", pid, comm, cpu, mem, etime) == 5) {
            json_t *process = json_object();
            json_object_set_new(process, "pid", json_string(pid));
            json_object_set_new(process, "name", json_string(comm));
            json_object_set_new(process, "cpu_usage", json_string(cpu));
            json_object_set_new(process, "ram_usage", json_string(mem));
            json_object_set_new(process, "uptime", json_string(etime));
            json_array_append_new(processes_array, process);
        }
    }

    pclose(fp);
    return processes_array;
}

void *health_check_thread(void *arg) {
    while (1) {
        pthread_mutex_lock(&health_mutex);
        for (int i = 0; i < service_count; i++) {
            if (strcmp(services[i].type, "http") == 0 || strcmp(services[i].type, "https") == 0) {
                services[i].status = check_http_health(services[i].url);
            } else if (strcmp(services[i].type, "tcp") == 0 || strcmp(services[i].type, "unix") == 0) {
                services[i].status = check_tcp_health(services[i].url);
            }
        }
        last_health_check = time(NULL);
        pthread_mutex_unlock(&health_mutex);
        sleep(refresh_time);
    }
    return NULL;
}

void load_services() {
    FILE *fp = fopen("service.json", "r");
    if (!fp) {
        fprintf(stderr, "Warning: Could not open service.json\n");
        return;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *data = malloc(fsize + 1);
    fread(data, 1, fsize, fp);
    data[fsize] = '\0';
    fclose(fp);
    
    json_t *root = json_loads(data, 0, NULL);
    free(data);
    if (!root) {
        fprintf(stderr, "Warning: Could not parse service.json\n");
        return;
    }
    
    json_t *services_array = json_object_get(root, "services");
    if (!services_array || !json_is_array(services_array)) {
        json_decref(root);
        return;
    }
    
    service_count = json_array_size(services_array);
    services = realloc(services, service_count * sizeof(Service));
    
    for (int i = 0; i < service_count; i++) {
        json_t *service_obj = json_array_get(services_array, i);
        const char *type = json_string_value(json_object_get(service_obj, "type"));
        const char *url = json_string_value(json_object_get(service_obj, "url"));
        const char *name = json_string_value(json_object_get(service_obj, "name"));
        
        if (type && url && name) {
            strncpy(services[i].type, type, sizeof(services[i].type));
            strncpy(services[i].url, url, sizeof(services[i].url));
            strncpy(services[i].name, name, sizeof(services[i].name));
            services[i].status = 0;
        }
    }
    
    json_decref(root);
}

void load_config() {
    FILE *fp = fopen("config.json", "r");
    if (!fp) return;
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *data = malloc(fsize + 1);
    fread(data, 1, fsize, fp);
    data[fsize] = '\0';
    fclose(fp);
    
    json_t *root = json_loads(data, 0, NULL);
    free(data);
    if (!root) return;
    
    refresh_time = json_integer_value(json_object_get(root, "refresh_time"));
    const char *ver = json_string_value(json_object_get(root, "version"));
    if (ver) strncpy(version, ver, sizeof(version));
    
    json_decref(root);
}

enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection, const char *url,
                    const char *method, const char *version, const char *upload_data,
                    size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }

    float cpu_usage = get_cpu_usage();
    double used_ram, total_ram;
    get_memory_usage(&used_ram, &total_ram);
    long uptime = get_system_uptime();
    char uptime_str[128];
    format_uptime(uptime, uptime_str, sizeof(uptime_str));
    
    pthread_mutex_lock(&health_mutex);
    json_t *service_health = json_object();
    for (int i = 0; i < service_count; i++) {
        json_object_set_new(service_health, services[i].name, json_boolean(services[i].status));
    }
    pthread_mutex_unlock(&health_mutex);
    
    json_t *logged_in_users = get_logged_in_users();
    json_t *top_processes = get_top_processes();
    
    json_t *root = json_object();
    json_t *cpu_obj = json_object();
    json_t *ram_obj = json_object();
    json_t *uptime_obj = json_object();

    json_object_set_new(cpu_obj, "usage", json_real(cpu_usage));
    json_object_set_new(root, "cpu", cpu_obj);

    json_object_set_new(ram_obj, "used", json_real(used_ram));
    json_object_set_new(ram_obj, "total", json_real(total_ram));
    json_object_set_new(root, "ram", ram_obj);

    json_object_set_new(root, "location", json_string(server_location));

    json_object_set_new(uptime_obj, "seconds", json_integer(uptime));
    json_object_set_new(uptime_obj, "readable", json_string(uptime_str));
    json_object_set_new(root, "uptime", uptime_obj);

    json_object_set_new(root, "service_health", service_health);
    json_object_set_new(root, "version", json_string(version));
    json_object_set_new(root, "logged_in_users", logged_in_users);
    json_object_set_new(root, "top_processes", top_processes);

    char *response = json_dumps(root, JSON_COMPACT);
    json_decref(root);

    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), response, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    MHD_add_response_header(mhd_response, "Access-Control-Allow-Origin", "*");
    
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
    MHD_destroy_response(mhd_response);
    return ret;
}

static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            float cpu_usage = get_cpu_usage();
            double used_ram, total_ram;
            get_memory_usage(&used_ram, &total_ram);
            long uptime = get_system_uptime();
            char uptime_str[128];
            format_uptime(uptime, uptime_str, sizeof(uptime_str));
            
            pthread_mutex_lock(&health_mutex);
            json_t *service_health = json_object();
            for (int i = 0; i < service_count; i++) {
                json_object_set_new(service_health, services[i].name, json_boolean(services[i].status));
            }
            pthread_mutex_unlock(&health_mutex);
            
            json_t *logged_in_users = get_logged_in_users();
            json_t *top_processes = get_top_processes();
            
            json_t *root = json_object();
            json_t *cpu_obj = json_object();
            json_t *ram_obj = json_object();
            json_t *uptime_obj = json_object();

            json_object_set_new(cpu_obj, "usage", json_real(cpu_usage));
            json_object_set_new(root, "cpu", cpu_obj);

            json_object_set_new(ram_obj, "used", json_real(used_ram));
            json_object_set_new(ram_obj, "total", json_real(total_ram));
            json_object_set_new(root, "ram", ram_obj);

            json_object_set_new(root, "location", json_string(server_location));

            json_object_set_new(uptime_obj, "seconds", json_integer(uptime));
            json_object_set_new(uptime_obj, "readable", json_string(uptime_str));
            json_object_set_new(root, "uptime", uptime_obj);

            json_object_set_new(root, "service_health", service_health);
            json_object_set_new(root, "version", json_string(version));
            json_object_set_new(root, "logged_in_users", logged_in_users);
            json_object_set_new(root, "top_processes", top_processes);

            char *data = json_dumps(root, JSON_COMPACT);
            json_decref(root);

            size_t data_len = strlen(data);
            unsigned char *buf = malloc(LWS_PRE + data_len);
            memcpy(buf + LWS_PRE, data, data_len);
            lws_write(wsi, buf + LWS_PRE, data_len, LWS_WRITE_TEXT);
            free(buf);
            free(data);

            sleep(WS_REFRESH_INTERVAL);
            lws_callback_on_writable(wsi);
            break;
        }

        default:
            break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "websocket",
        websocket_callback,
        0,
        4096,
    },
    { NULL, NULL, 0, 0 }
};

int main() {
    pthread_mutex_init(&health_mutex, NULL);
    get_server_location();
    load_config();
    load_services();
    
    pthread_t thread;
    pthread_create(&thread, NULL, health_check_thread, NULL);
    
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        PORT,
        NULL,
        NULL,
        &request_handler,
        NULL,
        MHD_OPTION_END
    );
    
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server on port %d\n", PORT);
        return 1;
    }
    
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = PORT + 1;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "Failed to create WebSocket context\n");
        MHD_stop_daemon(daemon);
        return 1;
    }

    printf("Healthcheck server started:\n");
    printf("HTTP API: http://localhost:%d\n", PORT);
    printf("WebSocket: ws://localhost:%d\n", PORT + 1);

    while (1) {
        lws_service(context, 100);
        usleep(10000);
    }

    lws_context_destroy(context);
    MHD_stop_daemon(daemon);
    return 0;
}
