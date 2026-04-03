NAME = inquisitor 

CC = gcc

OBJS_PATH=./build

FLAGS = -Wall -Werror -Wextra
DEP_FLAGS = -MMD -MP
#ADR_FLAGS = -fsanitize=address -g
CFLAGS = $(FLAGS) -I $(IDIR) $(DEP_FLAGS) #$(ADR_FLAGS)

SRC = inquisitor.c parse.c
IDIR = ./include 
OBJ = $(addprefix $(OBJS_PATH)/, ${SRC:.c=.o})
DEPS = ${OBJ:.o=.d}

all: $(NAME)

-include $(DEPS)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ 

$(OBJS_PATH)/%.o: %.c Makefile  
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo Cleaning...
	@rm -rf $(OBJS_PATH)

fclean: clean
	@rm -f $(NAME)
	@rm -f $(NAME_BONUS)

re: fclean all

droied:
	@echo
	@echo "By Droied"
	@echo

.PHONY: all clean fclean re droied 
