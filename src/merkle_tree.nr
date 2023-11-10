use dep::std;
use dep::std::collections::vec::Vec;

fn compute_merkle_root<N>(leaf: Field, index: Field, hash_path: [Field; N]) -> Field {
    
    let n = hash_path.len();
    let index_bits = index.to_le_bits(n as u32);
    let mut current = leaf;

    for i in 0..n{
      if(hash_path[i]!=-1){
        
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
         } else {
            (current, hash_path[i])
         };

        current = std::hash::poseidon::bn254::hash_2([hash_left, hash_right]);
        }
    };
    current
}

fn field_generator(addr_sk_gen : Field) -> Field {
    std::hash::poseidon::bn254::hash_1([addr_sk_gen])
}

/*
//old
fn generate_merkle_tree(cm_1_old: Field, cm_2_old: Field) -> ([Field; 7], Field, Field){
    
    //Generate a merkle tree of 7 cm
    let mut merkle_tree: [Field; 7] = [0; 7];
    let mut path_1: Field = 1;
    let mut path_2: Field = 2;

    merkle_tree[3] = 0;
    merkle_tree[4] = cm_1_old;
    merkle_tree[5] = cm_2_old;
    merkle_tree[6] = 1;
    merkle_tree[1] = std::hash::poseidon::bn254::hash_2([merkle_tree[3], merkle_tree[4]]);
    merkle_tree[2] = std::hash::poseidon::bn254::hash_2([merkle_tree[5], merkle_tree[6]]);
    merkle_tree[0] = std::hash::poseidon::bn254::hash_2([merkle_tree[1], merkle_tree[2]]);

    (merkle_tree, path_1, path_2)

}
*/

//generate a merkle_tree of seven elements (4 leaves)
fn generate_merkle_tree_seven(cm_1_old: Field, cm_2_old: Field) -> ([Field; 7], (Field, [Field; 100]), (Field, [Field; 100])){
    
    //Generate a merkle tree of 7 cm
    let mut merkle_tree: [Field; 7] = [0; 7];

    merkle_tree[6] = 1;
    merkle_tree[5] = cm_2_old;
    merkle_tree[4] = cm_1_old;
    merkle_tree[3] = 0;
    merkle_tree[2] = std::hash::poseidon::bn254::hash_2([merkle_tree[5], merkle_tree[6]]);
    merkle_tree[1] = std::hash::poseidon::bn254::hash_2([merkle_tree[3], merkle_tree[4]]);
    merkle_tree[0] = std::hash::poseidon::bn254::hash_2([merkle_tree[1], merkle_tree[2]]);

    let mut path_1_1: [Field; 100] = [-1; 100];
    path_1_1[0] = 0;
    path_1_1[1] = merkle_tree[2];

    let mut path_1_2: [Field; 100] = [-1; 100];
    path_1_2[0] = 1;
    path_1_2[1] = merkle_tree[1];

    let mut path_1: (Field, [Field; 100]) = (1, path_1_1);
    let mut path_2: (Field, [Field; 100]) = (2, path_1_2);

    (merkle_tree, path_1, path_2)
}

//generate merkle_tree of

fn generate_merkle_tree_bigger(cm_1_old: Field, cm_2_old: Field) -> ([Field; 255], (Field, [Field; 100]), (Field, [Field; 100])){
    
    //h = 8
    //number of nodes = 2^(h) - 1 = 255
    //number of leaves = 2^(h-1) = 128
    let mut merkle_tree: [Field; 255] = [0; 255];

    for i in 0..255{
        merkle_tree[i] = field_generator(i);
    }

    //set the first leaf
    merkle_tree[254 - 128 + 1] = cm_1_old;

    //set the last leaf
    merkle_tree[254] = cm_2_old;

    let mut path_1_1: [Field; 100] = [-1; 100];
    path_1_1[0] = merkle_tree[254 - 128 + 1 + 1];
    path_1_1[1] = merkle_tree[254 - 128 - ((128/2) + 1 )];
    path_1_1[2] = merkle_tree[254 - 128 - (128/2) - ((128/4) + 1)];
    path_1_1[3] = merkle_tree[254 - 128 - (128/2) - (128/4) - ((128/8) + 1)];
    path_1_1[4] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - ((128/16) + 1)];
    path_1_1[5] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - (128/16) - ((128/32) + 1)];
    path_1_1[6] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - (128/16) - (128/32) - ((128/64) + 1)];

    let mut path_1_2: [Field; 100] = [-1; 100];
    path_1_2[0] = merkle_tree[254 - 1];
    path_1_2[1] = merkle_tree[254 - 128 - 1];
    path_1_2[2] = merkle_tree[254 - 128 - (128/2) - 1];
    path_1_2[3] = merkle_tree[254 - 128 - (128/2) - (128/4) - 1];
    path_1_2[4] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - 1];
    path_1_2[5] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - (128/16) - 1];
    path_1_2[6] = merkle_tree[254 - 128 - (128/2) - (128/4) - (128/8) - (128/16) - (128/32) - 1];

    let mut path_1: (Field, [Field; 100]) = (0, path_1_1);
    let mut path_2: (Field, [Field; 100]) = (127, path_1_2);

    (merkle_tree, path_1, path_2)
}