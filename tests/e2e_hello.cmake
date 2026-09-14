file(MAKE_DIRECTORY "${WORK_DIR}")

execute_process(
    COMMAND "${GEN_HELLO}" "${WORK_DIR}/hello.ppc"
    RESULT_VARIABLE GEN_RC
    OUTPUT_VARIABLE GEN_OUT
    ERROR_VARIABLE GEN_ERR
)
if(NOT GEN_RC EQUAL 0)
    message(FATAL_ERROR "gen_hello failed rc=${GEN_RC}: ${GEN_ERR}")
endif()

execute_process(
    COMMAND "${SOSETTA}" "${WORK_DIR}/hello.ppc"
    RESULT_VARIABLE RUN_RC
    OUTPUT_VARIABLE RUN_OUT
    ERROR_VARIABLE RUN_ERR
)
if(NOT RUN_RC EQUAL 0)
    message(FATAL_ERROR "sosetta exited rc=${RUN_RC}: ${RUN_ERR}")
endif()

string(STRIP "${RUN_OUT}" RUN_TRIM)
if(NOT "x${RUN_TRIM}" STREQUAL "xHello from PowerPC!")
    message(FATAL_ERROR "stdout mismatch\n  got: [${RUN_TRIM}]\n  want: [Hello from PowerPC!]")
endif()

message(STATUS "e2e_hello: stdout matched (${RUN_TRIM})")