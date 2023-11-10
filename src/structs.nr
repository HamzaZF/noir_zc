use dep::std;
use dep::std::collections::vec::Vec;

struct Record {
    addr_pk: Field,
    payload: (u8, Field),
    rho: Field,
    r: Field,
    s: Field,
    cm: Field, //Poseidon
}

struct x {
    rt: Field, 
    sn_1_old: Field, 
    sn_2_old: Field, 
    cm_1_new: Field, 
    cm_2_new: Field, 
    v_pub: Field, 
    h_sig: Field, 
    h_1: Field, 
    h_2: Field,
}

struct a {
    path_1: (Field, [Field; 100]),//[Field; 2], //[Field; 8], 
    path_2: (Field, [Field; 100]),//[Field; 2], //[Field; 8],
    c_1_old: Record, 
    c_2_old: Record, 
    addr_sk_1_old: Field, 
    addr_sk_2_old: Field, 
    c_1_new: Record, 
    c_2_new: Record,
}