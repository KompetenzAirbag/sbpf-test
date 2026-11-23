#include "util/gen_types.h"

#define MAX_INSTR_CNT      ( 64UL )
#define MAX_INSTR_DATA_CNT ( 10240UL )
#define MAX_INSTR_ACC_CNT  ( 255UL )

typedef struct instr_acc_t {
    u16 index;
    u8  is_writable;
    u8  is_signer;
} instr_acc_t;

typedef struct instr_t
{
    u8  program_id_idx;

    u8  data[ MAX_INSTR_DATA_CNT ];
    u16 data_sz;

    u16 acc_cnt;
    instr_acc_t accs[ MAX_INSTR_ACC_CNT ];
} instr_t;

typedef struct txn_t
{
    ushort instr_cnt;

    instr_t instrs[ MAX_INSTR_CNT ];
} txn_t;

typedef enum txn_err_e
{
    TXN_SUCCESS = 0
} txn_err_e;

typedef enum instr_err_e
{
    INSTR_SUCCESS = 0
} instr_err_e;

instr_err_e
execute_instr( instr_t* instr )
{
    return INSTR_SUCCESS;
}

txn_err_e
execute_txn( txn_t* txn )
{
    for( ushort i=0; i < txn->instr_cnt; i++ ) {
        instr_t* instr = &txn->instrs[i];
    }
    return TXN_SUCCESS;
}
