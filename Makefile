RM := rm -rf
SSH2COM_TARGET := ssh2com
CONSOLE_TARGET := console
LAUNCH_SCRIPT  := debian/launch.sh
CP := cp
MKDIR := mkdir
CC := gcc
MV := mv
MAKE := make

# All of the sources participating in the build are defined here
-include src/ssh2com/subdir.mk
-include src/console/subdir.mk
-include objects.mk

override CFLAGS += -g3

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: sonic-ssh2com console

# Tool invocations
sonic-ssh2com: $(SSH2COM_OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -o "$(SSH2COM_TARGET)" $(SSH2COM_OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

console: $(CONSOLE_OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -o "$(CONSOLE_TARGET)" $(CONSOLE_OBJS) $(USER_OBJS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
install:
	$(MKDIR) -p $(DESTDIR)/usr/sbin
	$(MV) $(SSH2COM_TARGET) $(CONSOLE_TARGET) $(DESTDIR)/usr/sbin
	$(CP) $(LAUNCH_SCRIPT) $(DESTDIR)/usr/sbin

deinstall:
	$(RM) $(DESTDIR)/usr/sbin/$(SSH2COM_TARGET) $(DESTDIR)/usr/sbin/$(CONSOLE_TARGET)
	$(RM) -rf $(DESTDIR)/usr/sbin

clean:
	-$(RM) $(EXECUTABLES) $(SSH2COM_OBJS) $(CONSOLE_OBJS) $(C_DEPS) $(SSH2COM_TARGET) $(CONSOLE_TARGET)
	-@echo ' '

.PHONY: all clean dependents