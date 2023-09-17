import lief

from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.dse import DSEPathConstraint
from miasm.expression.expression import ExprMem, ExprId, ExprInt, ExprAssign
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_INT_XX
from miasm.core.interval import interval

from future.utils import viewitems


# SUMMARY:
# - Parses the machine code from address from the entry to address 0x14000501B
# - Finds every possible if statement path, from entry to 0x14000501B
# - Stores the variable expressions/constraints required to reach each if statement path (stuff like x=5, y>10, etc)



target_binary = "CorsairLLAccess64.sys"
stop_address = 0x14000501B

pe_info = lief.parse(target_binary)

for imported_library in pe_info.imports:
  print("Library name: " + imported_library.name)
  for func in imported_library.entries:
    if not func.is_ordinal:
      print(func.name)
    print(hex(func.iat_address))

# Convert strategy to the correct value
strategy = DSEPathConstraint.PRODUCE_SOLUTION_CODE_COV #{
   # "code-cov": DSEPathConstraint.PRODUCE_SOLUTION_CODE_COV,
    #"branch-cov": DSEPathConstraint.PRODUCE_SOLUTION_BRANCH_COV,
   # "path-cov": DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV,
# }[args.strategy]

loc_db = LocationDB()

# Map the shellcode
run_addr = pe_info.entrypoint
machine = Machine("x86_64")
jitter = machine.jitter(loc_db, "python")

with open(target_binary, "rb") as fdesc:
    
    for page in range(0,pe_info.virtual_size,0x1000):
        fdesc.seek(page, 0)
        jitter.vm.add_memory_page(
            0x140000000 + page,
            PAGE_READ | PAGE_WRITE,
            bytes(pe_info.get_content_from_virtual_address(page, 0x1000)),
            "Binary"
        )

# Expect a binary with one argument on the stack
jitter.init_stack()


# push Argument
jitter.push_uint64_t(0)

# push return address
def code_sentinelle(jitter):
    jitter.running = False
    return False

ret_addr = 0x1337beef
jitter.add_breakpoint(ret_addr, code_sentinelle)
jitter.push_uint64_t(ret_addr)


# Init the jitter
jitter.init_run(run_addr)

# Init a DSE instance with a given strategy
dse = DSEPathConstraint(machine, loc_db, produce_solution=strategy)
dse.attach(jitter)

dse.symbolize_memory(interval([(0x140000000, 0x140000000 + pe_info.virtual_size - 1)]))

# Concretize everything except the argument
regs = jitter.lifter.arch.regs
RCXtest = ExprId("RCXtest", 64)

dse.update_state({
    dse.lifter.arch.regs.RCX: RCXtest,
})

# test breakpoint

def test_bp(jitter):
  #  print("pc: " + hex(jitter.pc))

    return False

jitter.add_breakpoint(stop_address, test_bp)

# Explore solutions
todo = set([ExprInt(run_addr, 8)])
done = set()
snapshot = dse.take_snapshot()

# ignore this line

reaches = set()

for i in range(100):

    # Restore state, while keeping already found solutions

    dse.restore_snapshot(snapshot, keep_known_solutions=True)

    # reset jitter
    jitter.init_run(run_addr)

    # Launch

    jitter.continue_run()


    # Obtained solutions are in dse.new_solutions: identifier -> solution model
    # The identifier depends on the strategy:
    # - block address for code coverage
    # - last edge for branch coverage
    # - execution path for path coverage

    for solution, model in viewitems(dse.new_solutions):

        print("Found a solution to reach: %s" % str(solution))
        print(hex(loc_db.get_location_offset(solution.loc_key)))

        # Get the argument to use as a Miasm Expr (RCXtest)
        sol_value = model.eval(dse.z3_trans.from_expr(dse.lifter.arch.regs.RCX)).__str__()

        # Display info and update storages
#        print("\tARG = %s" % sol_value)
 #       todo.add(sol_expr)
        reaches.add(solution)

print(
    "Found %d input, to reach %d element of coverage" % (
        len(done),
        len(reaches)
    )
)