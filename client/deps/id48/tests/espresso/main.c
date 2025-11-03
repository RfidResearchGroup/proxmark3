


#include <stdio.h>
#include <stdbool.h>
#include "verify_espresso.h"
#include "id48.h"

int main(void) {
    bool result = true;

    if (result) {
        printf("Verifying Espresso Results...\n");
        result = verify_espresso_results();
        printf("Verifying Espresso Results:  %s\n",
            result ? "SUCCESS" : "----> FAILURE <----"
        );
    }
    // if (result) {
    //     printf("Hello2...\n");
    //     generate_all_lut_espresso_files();
    // }

    return result ? 0 : -120;
}
