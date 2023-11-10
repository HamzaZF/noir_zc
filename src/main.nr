use dep::std;
use dep::std::collections::vec::Vec;
mod structs;
mod merkle_tree;
mod hash;

fn get_h(h_sig: Field, addr_sk_old: Field) -> Field{
    std::hash::poseidon::bn254::hash_2([addr_sk_old, h_sig])
}

fn field_generator(addr_sk_gen : Field) -> Field {
    std::hash::poseidon::bn254::hash_1([addr_sk_gen])
}

fn h_sig_generator(h_sig_gen : Field) -> Field {
    std::hash::poseidon::bn254::hash_1([h_sig_gen])
}

fn get_sn(rho: Field, addr_sk: Field) -> Field{
    std::hash::poseidon::bn254::hash_2([addr_sk, rho])
}

fn get_cm(addr_pk: Field, rho: Field, r: Field, v: Field) -> Field{
    let cm_0 = std::hash::poseidon::bn254::hash_2([addr_pk, rho]);
    let cm_1 = std::hash::poseidon::bn254::hash_2([r, cm_0]);
    let cm = std::hash::poseidon::bn254::hash_2([cm_1, v]);
    cm
}

fn record_generator(addr_pk : Field, addr_sk: Field, r : Field, rho : Field, v : Field) -> structs::Record{
    
    let sn = get_sn(rho, addr_sk);

    let cm = get_cm(addr_pk, rho, r, v);

    structs::Record{
        addr_pk: addr_pk,
        payload: (0,v),
        rho: rho,
        r: r,
        s: sn,
        cm: cm,
    }
}

fn addr_pk_generator(addr_sk: Field) -> Field{
    std::hash::poseidon::bn254::hash_2([addr_sk, 0])
}

fn a_x_generator(addr_sk_1_old_seed: Field,
               addr_sk_2_old_seed: Field, 
               addr_sk_1_new_seed: Field, 
               addr_sk_2_new_seed: Field,
               r_1_old_seed: Field,
               r_2_old_seed: Field,
               r_1_new_seed: Field,
               r_2_new_seed: Field,
               rho_1_old_seed: Field,
               rho_2_old_seed: Field,
               rho_1_new_seed: Field,
               rho_2_new_seed: Field,
               v_1_old: Field,
               v_2_old: Field,
               v_1_new: Field,
               v_2_new: Field,
               v_pub: Field,
               h_sig_seed: Field,

) -> (structs::a, structs::x){

    let addr_sk_1_old: Field = field_generator(addr_sk_1_old_seed);
    let addr_sk_2_old: Field = field_generator(addr_sk_2_old_seed);
    let addr_pk_1_old: Field = addr_pk_generator(addr_sk_1_old);
    let addr_pk_2_old: Field = addr_pk_generator(addr_sk_2_old);
    let r_1_old: Field = field_generator(r_1_old_seed);
    let r_2_old: Field = field_generator(r_2_old_seed);
    let rho_1_old: Field = field_generator(rho_1_old_seed);
    let rho_2_old: Field = field_generator(rho_2_old_seed);
    let c_1_old: structs::Record = record_generator(addr_pk_1_old, addr_sk_1_old, r_1_old, rho_1_old, v_1_old);
    let c_2_old: structs::Record = record_generator(addr_pk_2_old, addr_sk_2_old, r_2_old, rho_2_old, v_2_old);
    let sn_1_old = c_1_old.s;
    let sn_2_old = c_2_old.s;

    let addr_sk_1_new: Field = field_generator(addr_sk_1_new_seed);
    let addr_sk_2_new: Field = field_generator(addr_sk_2_new_seed);
    let addr_pk_1_new: Field = addr_pk_generator(addr_sk_1_new);
    let addr_pk_2_new: Field = addr_pk_generator(addr_sk_2_new);
    let r_1_new: Field = field_generator(r_1_new_seed);
    let r_2_new: Field = field_generator(r_2_new_seed);
    let rho_1_new: Field = field_generator(rho_1_new_seed);
    let rho_2_new: Field = field_generator(rho_2_new_seed);
    let c_1_new: structs::Record = record_generator(addr_pk_1_new, addr_sk_1_new, r_1_new, rho_1_new, v_1_new);
    let c_2_new: structs::Record = record_generator(addr_pk_2_new, addr_sk_2_new, r_2_new, rho_2_new, v_2_new);
    let cm_1_new = c_1_new.cm;
    let cm_2_new = c_2_new.cm;

    let v_pub = v_pub;

    let h_sig = h_sig_generator(h_sig_seed);

    let h_1 = get_h(h_sig, addr_sk_1_old);

    let h_2 = get_h(h_sig, addr_sk_2_old);

    let (merkle_tree, path_1, path_2) : ([Field; 7], (Field, [Field; 100]), (Field, [Field; 100])) = merkle_tree::generate_merkle_tree_seven(c_1_old.cm, c_2_old.cm);

    let rt = merkle_tree[0];

    let x = structs::x{
        rt: rt,
        sn_1_old: sn_1_old,
        sn_2_old: sn_2_old,
        cm_1_new: cm_1_new,
        cm_2_new: cm_2_new,
        v_pub: v_pub,
        h_sig: h_sig,
        h_1: h_1,
        h_2: h_2,
    };

    let a = structs::a{
        path_1: path_1,
        path_2: path_2,
        c_1_old: c_1_old,
        c_2_old: c_2_old,
        addr_sk_1_old: addr_sk_1_old,
        addr_sk_2_old: addr_sk_2_old,
        c_1_new: c_1_new,
        c_2_new: c_2_new,
    };

    (a, x)
}

fn get_siblings_from_merkle_tree<N>(merkle_tree: [Field; N], leaf: Field){
    let mut siblings: [Field; N] = [-1; N]; //change if necessary
    for i in 0..merkle_tree.len(){
        if merkle_tree[i]==leaf{
            let mut l: u32 = (i as u32);
            for j in 0..merkle_tree.len(){
                if l!= 0{
                    let index = (l%2==0) as bool;
                    if !index{
                        let right = merkle_tree[l+1];
                        siblings[j] = right;
                    }else{
                        let left = merkle_tree[l-1];
                        siblings[j] = left;
                    }
                    l = (((l as u32) - 1)/2 as u32);
                }
            }
        }
    }

}

fn proof<N>(a: structs::a, x: structs::x){

    let c_old = [a.c_1_old, a.c_2_old];
    
    let sn_old = [x.sn_1_old, x.sn_2_old];
    let path = [a.path_1, a.path_2];
    
    let addr_sk_old = [a.addr_sk_1_old, a.addr_sk_2_old];
    let addr_pk_old = [a.c_1_old.addr_pk, a.c_2_old.addr_pk];
    let addr_pk_new = [a.c_1_new.addr_pk, a.c_2_new.addr_pk];
    let c_new = [a.c_1_new, a.c_2_new];
    let h = [x.h_1, x.h_2];

    /*
    let mut cm_1_old_siblings: [Field; 16] = [-1; 16]; //change if necessary
    for i in 0..merkle_tree.len(){
        if merkle_tree[i]==c_old[0].cm{
            let mut l: u32 = (i as u32);
            for j in 0..merkle_tree.len(){
                if l!= 0{
                    let index = (l%2==0) as bool;
                    if !index{
                        let right = merkle_tree[l+1];
                        cm_1_old_siblings[j] = right;
                    }else{
                        let left = merkle_tree[l-1];
                        cm_1_old_siblings[j] = left;
                    }
                    l = (((l as u32) - 1)/2 as u32);
                }
            }
        }
    }

    let mut cm_2_old_siblings: [Field; 16] = [-1; 16]; //change if necessary
    for i in 0..merkle_tree.len(){
        if merkle_tree[i]==c_old[1].cm{
            let mut l: u32 = (i as u32);
            for j in 0..merkle_tree.len(){
                if l!= 0{
                    let index = (l%2==0) as bool;
                    if !index{
                        let right = merkle_tree[l+1];
                        cm_2_old_siblings[j] = right;
                    }else{
                        let left = merkle_tree[l-1];
                        cm_2_old_siblings[j] = left;
                    }
                    l = (((l as u32) - 1)/2 as u32);
                }
            }
        }
    }*/
    
    let hash_path = [path[0].1, path[1].1];
    
    for i in 0..2 {
        //1) path_i is a valid authentication path for leaf cm_i_old with respect to root rt, in a CRH-based merkle tree
        
        let hash_path = hash_path[i];
        let index = path[i].0;

        let merkle_root = merkle_tree::compute_merkle_root(c_old[i].cm, index, hash_path);

        assert(merkle_root == x.rt);
        
        //2) the address secret key a_sk_i_old matches the address public key of c_i_old, i.e.

        let a_pk_i_old_computed = addr_pk_generator(addr_sk_old[i]);

        assert(a_pk_i_old_computed == addr_pk_old[i]);

        //3) the serial number sn_i_old of c_i_old is computed correctly
        
        let sn_i_old_computed: Field = get_sn(c_old[i].rho, addr_sk_old[i]);

        assert(sn_i_old_computed == sn_old[i]);

        //4) the commitment of c_i_old is well-formed
        
        let cm_i_old_computed = get_cm(addr_pk_old[i], c_old[i].rho, c_old[i].r, c_old[i].payload.1);

        assert(cm_i_old_computed == c_old[i].cm);
        
        //5) the commitment of c_i_new is well-formed

        let cm_i_new_computed = get_cm(addr_pk_new[i], c_new[i].rho, c_new[i].r, c_new[i].payload.1);

        assert(cm_i_new_computed == c_new[i].cm);

        //6) the address secret key a_sk_i_old ties h_sig to h_i

        let h_computed = get_h(x.h_sig, addr_sk_old[i]);

        assert(h_computed == h[i]);
        
    }
    
    //B) balance is preserved : v_1_new + v_2_new + v_pub = v_1_old + v_2_old

    let left_sum = a.c_1_new.payload.1 + a.c_2_new.payload.1 + x.v_pub;
    let right_sum = a.c_1_old.payload.1 + a.c_2_old.payload.1;

    assert(left_sum == right_sum);

}


/*Real main function (but it crashes)*/
/*
fn main(witness: structs::a, statement: pub structs::x){

    proof(witness, statement);
}
*/

fn main(){}


#[test]
fn main_test(){
    let addr_sk_1_old_seed = 1;
    let addr_sk_2_old_seed = 1;
    let addr_sk_1_new = 10;
    let addr_sk_2_new = 10;
    let r_1_old_seed = 2;
    let r_2_old_seed = 3;
    let r_1_new_seed = 4;
    let r_2_new_seed = 5;
    let rho_1_old_seed = 21;
    let rho_2_old_seed = 22;
    let rho_1_new_seed = 23;
    let rho_2_new_seed = 24;
    let v_1_old = 30;
    let v_2_old = 15;
    let v_1_new = 20;
    let v_2_new = 20;
    let v_pub = 5;
    let h_sig_seed = 30;

    let (witness, statement) = a_x_generator(addr_sk_1_old_seed, 
                                           addr_sk_2_old_seed, 
                                           addr_sk_1_new, 
                                           addr_sk_2_new,
                                           r_1_old_seed,
                                           r_2_old_seed,
                                           r_1_new_seed,
                                           r_2_new_seed,
                                           rho_1_old_seed,
                                           rho_2_old_seed,
                                           rho_1_new_seed,
                                           rho_2_new_seed,
                                           v_1_old,
                                           v_2_old,
                                           v_1_new,
                                           v_2_new,
                                           v_pub,
                                           h_sig_seed,
                                           );
    
    proof(witness, statement);

    //std::println("done");
}

/*
#[test]
fn test_main_automated(){

    let addr_sk_1_old_seed = 1;
    let addr_sk_2_old_seed = 1;
    let addr_sk_1_new = 10;
    let addr_sk_2_new = 10;
    let r_1_old_seed = 2;
    let r_2_old_seed = 3;
    let r_1_new_seed = 4;
    let r_2_new_seed = 5;
    let rho_1_old_seed = 21;
    let rho_2_old_seed = 22;
    let rho_1_new_seed = 23;
    let rho_2_new_seed = 24;
    let v_1_old = 30;
    let v_2_old = 15;
    let v_1_new = 20;
    let v_2_new = 20;
    let v_pub = 5;
    let h_sig_seed = 30;

    let (witness, statement, merkle_tree) = a_x_tree_generator(addr_sk_1_old_seed, 
                                           addr_sk_2_old_seed, 
                                           addr_sk_1_new, 
                                           addr_sk_2_new,
                                           r_1_old_seed,
                                           r_2_old_seed,
                                           r_1_new_seed,
                                           r_2_new_seed,
                                           rho_1_old_seed,
                                           rho_2_old_seed,
                                           rho_1_new_seed,
                                           rho_2_new_seed,
                                           v_1_old,
                                           v_2_old,
                                           v_1_new,
                                           v_2_new,
                                           v_pub,
                                           h_sig_seed,
                                           );

    proof(witness, statement, merkle_tree);

}
*/
