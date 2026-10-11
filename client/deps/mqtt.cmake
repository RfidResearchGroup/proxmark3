add_library(pm3rrg_rdv4_mqtt STATIC
        mqtt/mqtt.c
        mqtt/mqtt_pal.c
        )

target_compile_definitions(pm3rrg_rdv4_mqtt PRIVATE WAI_PM3_TUNED)
target_include_directories(pm3rrg_rdv4_mqtt INTERFACE mqtt)
target_compile_options(pm3rrg_rdv4_mqtt PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_mqtt PROPERTY POSITION_INDEPENDENT_CODE ON)
