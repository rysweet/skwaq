#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

/* CWE-416: Use-after-free via dangling raw pointer from shared_ptr */
class Resource {
public:
    char data[256];
    Resource(const char *d) { strncpy(data, d, sizeof(data) - 1); }
};

void process_resource(const char *raw) {
    Resource *raw_ptr;
    {
        std::shared_ptr<Resource> res = std::make_shared<Resource>(raw);
        raw_ptr = res.get();  /* Dangling: shared_ptr scope ends here */
    }
    /* CWE-416: raw_ptr is dangling, Resource already destroyed */
    printf("Data: %s\n", raw_ptr->data);
}

/* CWE-120: Buffer overflow in C++ with C-style arrays */
class Logger {
    char buffer_[128];
public:
    void log(const char *msg) {
        strcpy(buffer_, msg);  /* CWE-120: no bounds check */
    }
};

/* CWE-190: Integer overflow in vector allocation */
void process_items(unsigned int count) {
    /* If count * sizeof(int) overflows, vector allocates too little */
    std::vector<int> items(count);
    for (unsigned int i = 0; i < count; i++) {
        items[i] = (int)i;
    }
}

/* CWE-78: Command injection via string concatenation */
void run_command(const std::string &user_input) {
    std::string cmd = "grep " + user_input + " /etc/passwd";
    system(cmd.c_str());  /* Injection via string concatenation */
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_resource(argv[1]);

        Logger logger;
        logger.log(argv[1]);

        run_command(argv[1]);
    }
    return 0;
}
