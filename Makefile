CC     = gcc
SRCDIR = $(PWD)/src/server
OBJDIR = $(PWD)/build
SRCS   = $(wildcard $(SRCDIR)/*.c)
OBJS   = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

CFLAGS = -O3 -Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing \
	 -fPIC -pipe -std=gnu99 -Wunused -Wcomment -Wchar-subscripts         \
	 -Wuninitialized -Wcast-qual -Wcast-align -Wwrite-strings            \
	 -Wstack-protector -fstack-protector-all -Wno-unknown-pragmas        \
	 -Wformat-security -Wsign-conversion -g -msse4 -D_GNU_SOURCE         \
	 -D_XOPEN_SOURCE=700
CFLAGS += -I$(RTE_SDK)/build/include

LDFLAGS = -L$(RTE_SDK)/build/lib -Wl,--as-needed

# DPDK libraries, do not reorder
RTE_LIBS := rte_distributor rte_kni rte_pipeline rte_table rte_port \
            rte_timer rte_hash rte_lpm rte_power rte_acl rte_meter  \
            rte_sched m rt rte_kvargs rte_mbuf rte_ip_frag ethdev   \
            rte_eal rte_mempool rte_ring rte_cmdline     \
            rte_cfgfile rte_pmd_bond rte_pmd_vmxnet3_uio            \
            rte_pmd_i40e rte_pmd_ixgbe           \
            rte_pmd_e1000 rte_pmd_ring rt m pthread dl

LIBS += -Wl,--whole-archive
LIBS += $(foreach rte_lib, $(RTE_LIBS), $(shell echo -Wl,-l$(rte_lib)))
LIBS += -Wl,--no-whole-archive

TARGET = udpecho

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) $(OBJS) -o $(OBJDIR)/$@

$(OBJS): $(SRCS) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)

over: clean all

.PHONY: clean all over
