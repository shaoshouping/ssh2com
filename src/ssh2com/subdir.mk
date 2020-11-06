# Add inputs and outputs from these tool invocations to the build variables 
CC := gcc

C_SRCS += \
../src/ssh2com/fxgl_session.c \
../src/ssh2com/fxgl_util.c \
../src/ssh2com/fxgl_main.c \
../src/ssh2com/log.c

SSH2COM_OBJS += \
./src/ssh2com/fxgl_session.o \
./src/ssh2com/fxgl_util.o \
./src/ssh2com/fxgl_main.o \
./src/ssh2com/log.o

C_DEPS += \
./src/ssh2com/fxgl_session.d \
./src/ssh2com/fxgl_util.d \
./src/ssh2com/fxgl_main.d \
./src/ssh2com/log.d

# Each subdirectory must supply rules for building sources it contributes
src/ssh2com/%.o: ../src/ssh2com/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' 