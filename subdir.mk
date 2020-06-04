################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../cryptoPAN.c \
../libAnonLua.c \
../libAnonLuaHelpers.c \
../linktype.c \
../pcapngw.c 

OBJS += \
./cryptoPAN.o \
./libAnonLua.o \
./libAnonLuaHelpers.o \
./linktype.o \
./pcapngw.o 

C_DEPS += \
./cryptoPAN.d \
./libAnonLua.d \
./libAnonLuaHelpers.d \
./linktype.d \
./pcapngw.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


