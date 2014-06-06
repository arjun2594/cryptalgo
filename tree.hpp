/* This program is for defining and constructing a tree */
//---Author -- Arjun <arjun2594@gmail.com>

#include<stdio.h>
#include<openssl/bn.h> //For BIGNUM datatype
#include<math.h> // For log2 
#include<openssl/dh.h> // For Diffie Hellman Protocol
#include<openssl/engine.h> // For the computation of keys invovled in Diffie hellman protocol

#define MAX_NODES 10

class tree
{
  
 private:
  struct node
  {
    int level; // Used to store the level of each node
    int nodeid; // Used to store a unique nodeid.
    node *child[2]; // The left child is child[0] and right child is child[1]
    node * parent;
    struct node* copath[MAX_NODES+1];
    struct node* keypath[MAX_NODES+1];
    DH *dh;
    unsigned char *group_key;
  } *root, *n, *temp, *sponsor;

  int keypath_index,copath_index;
  
  int no_of_dh_actions; //Metric for analysis and comparison against the other values.
  
  struct node_table //structure for storing all the leaves
  {
    struct node *node [MAX_NODES];
    int nodeid [MAX_NODES];
    bool reset[MAX_NODES];
  }nt;
  
  struct intermediate_node_table // structure for storing all the intermediate nodes
  {
    struct node* node [MAX_NODES];
    int nodeid[MAX_NODES];
    bool reset[MAX_NODES];
  }inter_nt;
  
  int no_of_leaves; // Stores the number of leaves in the tree
  int node_id_counter; // Stores the incremental id to be stored for the nodes.
  int nt_counter; // Index to the nodetable
  int intermediate_node_id_counter; // Stores the incremental id for all the nodes.
  int broadcast_count; // Stores the number of broadcasts
  
 public:
  tree();
  void reset_dh_counter(); // Reset the no of DH operations performed
  node* create_node(); // Create a new node
  int create_tree (int noofnodes); //Used for initially creating a tree;
  int add_to_tree (); // For adding a node or a set of nodes to a tree
  int delete_from_tree (int nodeid); // For deleting a node or a set of nodes from a tree;
  int get_max_id(); // Returns the maximum nodeid
  int get_max_intermediate_id(); // Returns the maximum intermediate id
  int get_broadcast_count(); // Returns the broadcast count
  node* find_node_by_id (int nodeid); // Find node by given id
  void insert_into_node_table (node *node, int nodeid); // Insert node into table
  void delete_from_node_table (int nodeid); // Delete node with nodeid from table
  void insert_into_intermediate_node_table(node* n, int nodeid); // Insert intermediate node into table
  void delete_from_intermediate_node_table(int nodeid); // Delete intermediate node from table
  int keygen(node *); // For generating the keys for a particular node 
  int compute_shared_key(node *); // For computing the shared key at each node
  node* get_sibling(node *e); // For getting the sibling of each node
  int tree_height(); // Returns the tree height
  int get_no_of_dh_actions(); // Returns the number of DH actions performed in one instance of the tree.
  void reset_all_keys(); // Reset the keys of the nodes lying in the keypath of the sponsor
  void broadcast(); // Used for broadcasting the changes to all the nodes that are changed.
  void setstatus(char table, bool resetstatus); // Method for resetting the status of key change 
  
  void keypath_reset(node *n);
  void copath_reset(node *n);
  void print(node *n);
  void inorder(node *n);
  void preorder(node *n);
  node* getkeypath(node *n);
  node* getcopath(node *n);
  void add_keypath(node *n);
  void add_copath(node *n);
  void print_keypath(node*);
  void print_copath(node*);
  void sponsor_ins(node *ins_pt);
  void sponsor_del(node *del);
};

tree :: tree()
{
  root = NULL;
  // Set all the counters to zero
  no_of_leaves = 0;
  node_id_counter = 0;
  nt_counter = 0;
  intermediate_node_id_counter = 0;
  broadcast_count = 0; 
}

int tree :: get_broadcast_count() // Return the broadcast count in the network
{
  return broadcast_count;
}

void tree :: setstatus(char table, bool resetstatus) // Table value should be 'l' for leaf and 'i' for intermediate nodes
{                                                    // Used for setting the reset status for each node in the network    
  if(table == 'l')
    for (int i = 0; i<MAX_NODES; i++)
      nt.reset[i] = resetstatus;
  else
    for(int i = 0; i<MAX_NODES; i++)
      inter_nt.reset[i] = resetstatus;
}

void tree:: broadcast() // Used for broadcasting the change to each network node.
{
  setstatus('l', false); // Mark all the nodes to be reset 
  for(int i = 0; i < MAX_NODES + 1 ; i++)
  {
    for(int j = 0;j< MAX_NODES + 1; j++)
    {
      for(int k = 0;k < MAX_NODES +1; k++)
        if(sponsor -> keypath[i] == nt.node[j] -> keypath [k] || nt.node[j] -> copath[k])
          if(!nt.reset[j])
          {
            keygen(nt.node[j] -> keypath[k]);
            nt.reset[j] = true;
            broadcast_count ++;
          }
    }
  }
  setstatus('l',true); // Set all the status flags back to false
}

int tree :: create_tree(int n) // Create the initial tree.
{
  for(int i = 0; i<n; i++)
    add_to_tree();
  reset_dh_counter(); // Clear the DH counter after the initial tree is constructed
  broadcast_count = 0; // Reset the broadcast count after the initial tree construction
}

int tree :: get_no_of_dh_actions() // Return the no of Diffie Hellan Operations
{
  return no_of_dh_actions;
}

int tree :: tree_height() // Return the tree height
{
  return int(floor(log2(no_of_leaves)));
}
  
tree :: node* tree :: create_node () // Create a new node
{
  n = new node;
  no_of_leaves++;
  n -> nodeid = node_id_counter++;
  insert_into_node_table (n, n->nodeid);
  keygen(n);
}

void tree :: reset_all_keys() // Resets the keys of nodes in the key path of the sponsor
{
  int iter = 0;
  for (iter = 0; iter < MAX_NODES+1; iter++)
    keygen(sponsor ->  keypath[iter]);
}

int tree :: add_to_tree () // Method is used for adding nodes to the key tree
{
  reset_all_keys(); // Reset the current network scenario
  create_node (); // Create a new node
  
  if(root == NULL) //This is the first node
  {
    root = n;
    root -> parent = NULL;
    root -> child[0] = NULL;
    root -> child[1] = NULL;
  }
  
  else if((log2(tree_height ()) == double(floor(log2(tree_height ())))) ) // If tree is complete, attach new node to the root
  {
    //Standard boilerplate for insertion
    temp = root; 
    root = new node;
    root -> nodeid = intermediate_node_id_counter++;
    insert_into_intermediate_node_table (root, root -> nodeid);
    root -> child [0] = temp;
    root -> child [1] = n;
    root -> child[1] -> parent = root;
    root -> child[0] -> parent = root;
  }
  
  else if (no_of_leaves %2 == 0) // Tree has even number of nodes -- The default case is split into two - One for odd no of nodes and other for even no of nodes
  {
    temp = find_node_by_id(get_max_id()); // Get the rightmost node;
    node *inter = temp -> parent; // Get it's parent
    temp = new node; // Create a new supplementary node
    temp -> nodeid = intermediate_node_id_counter++;
    insert_into_intermediate_node_table(temp, temp -> nodeid);
    temp -> parent = inter -> parent; // Make this node to point to the parent of the original node
    temp -> child[0] = inter; // Make the original node its child
    inter -> parent = temp; // Make the new node its parent
    temp -> child[1] = n; // Make the incoming node the child of the newly created node
    n -> parent = temp; //
  }

  else
  {
    temp = find_node_by_id(get_max_id()); //Get the rightmost node;
    node *inter = temp -> parent;
    inter -> child[1] = n; // Assign this node as the parent of the shallowest rightmost node;
  }
  
}

int tree :: delete_from_tree(int nodeid) // Delete a node from tree - Takes nodeid as input
{
  temp = find_node_by_id (nodeid);

  if (temp == NULL)
    return -1; 
  else
  {
    temp -> parent = get_sibling(temp);
    delete_from_node_table(temp -> nodeid); // Delete the entry from node table also
    delete_from_intermediate_node_table(temp->parent->nodeid); //Delete the parent from the intermediate node table
    delete temp;
    reset_all_keys();
  }
}

tree :: node* tree :: find_node_by_id (int nodeid) //Used for finding a given node with its id
{
  for(int i = 0; i < no_of_leaves ; i++)
  {
    if(nt.nodeid[i] == nodeid)
      return nt.node[i];
  }
  return NULL; // returns NULL on not found
}

int tree :: get_max_id () // Function returns the maximum nodeid thus far
{
  int temp = -1;
  for (int i = 0 ; i < node_id_counter; i++)
    if( nt.nodeid[i] > temp)
      temp = nt.nodeid[i];
  return temp;
}

int tree :: get_max_intermediate_id () // Function returns the maximum nodeid thus far
{
  int temp = -1;
  for (int i = 0 ; i < intermediate_node_id_counter; i++)
    if( inter_nt.nodeid[i] > temp)
      temp = inter_nt.nodeid[i];
  return temp;
}

void tree :: insert_into_node_table (node *node, int nodeid) // inserting a node into the node table
{
  nt.node[nt_counter] = node;
  nt.nodeid[nt_counter++] = nodeid;
}
    
void tree :: delete_from_node_table (int nodeid) // Delete an entry from the node table 
{
  for (int i = 0; i<no_of_leaves; i++)
    if(nt.nodeid[i] == nodeid)
    {
      nt.nodeid[i] = -1; //set invalid nodeid
      nt.node[i] = NULL; 
    }
}

int tree :: keygen(node *n) // Generate the keys for a given node
{
  for (int i = 0; i < MAX_NODES; i++)
    if(nt.node[i] == n)
      return DH_generate_key(n -> dh);
    else
    {
      n->dh->priv_key = (BIGNUM*)n->child[0]->group_key;
      return DH_generate_key(n -> dh);
    }
  compute_shared_key(n);
}

int tree :: compute_shared_key(node *n) // Compute the shared key for a given node
{
  node *sibling = get_sibling(n);
  return DH_compute_key(n -> group_key, (sibling -> dh) -> pub_key, n -> dh); // Compute the key for each node.
}

tree :: node* tree :: get_sibling(node *n) // Method to get the sibling of a particular node
{
  node* temp = n -> parent;
  if(n == temp -> child[0])
    return n -> child[1];
  else
    return n -> child[0];
}

//---Author - Arun <arunnarasimhan94@gmail.com>

void tree :: keypath_reset(node *n)
{
  keypath_index=-1;
}

void tree :: copath_reset(node *n)
{
  copath_index=-1;
}

void tree :: print(node *n)
{
  printf("\nInorder traversal : ");
  inorder(n);
  printf("\nPreorder traversal : ");
  preorder(n);
}

void tree :: inorder(node *n)
{
  node *prs=n;
  while(prs!=NULL)
  {
    inorder(prs->child[0]);
    printf("%d", prs->nodeid);  
    inorder(prs->child[1]);         
  }
}

void tree :: preorder(node *n)
{
  node *prs=n;
  while(prs!=NULL)
  {
    printf("%d", prs->nodeid);
    preorder(prs->child[0]); 
    preorder(prs->child[1]);         
  }
}

tree :: node* tree :: getkeypath(node *n)
{
  keypath_reset(n);
  add_keypath(n);
  print_keypath(n);
}

tree :: node* tree :: getcopath(node *n)
{
  copath_reset(n);
  add_copath(n);
  print_copath(n);
}

void tree :: add_keypath(node *n)
{
  while(n!=NULL)
  {
    n -> keypath [++keypath_index] = n;
    n = n -> parent;            
  }
  n -> keypath[keypath_index+1] = NULL;
}

void tree :: add_copath(node *n)
{     
  while((n->parent)!=NULL)
  {
    n->copath[copath_index] = get_sibling(n); 
    n=n->parent;            
  }
  n->copath[copath_index+1]=NULL;
}
  
void tree :: print_keypath(node* n)
{
  printf("\nNodes in key path : ");
  for(int i=0;i<=keypath_index;i++)
  {
    printf("%d",n -> keypath[i]->nodeid);
  }
}

void tree :: print_copath(node *n)
{
  printf("\n nodes in co path : ");
  for(int i=0;i<=copath_index;i++)
  {
    printf("%d",n->copath[i]->nodeid);
  }
}

void tree :: sponsor_ins(node *ins_pt)
{
  node *tmp=ins_pt;
  while(tmp->child[1]!=NULL  && tmp->child[0]!=NULL)
  {
    if(tmp->child[1]!=NULL)
    {
      tmp=tmp->child[1];                
    }   
    else if(tmp->child[0]!=NULL)
    {
      tmp=tmp->child[0];                
    }                       
  }
  sponsor=tmp;
}

void tree :: sponsor_del(node *del)
{
  node *tmp=get_sibling(del);
  while(tmp->child[1]!=NULL  && tmp->child[0]!=NULL)
  {
    if(tmp->child[1]!=NULL)
    {
      tmp=tmp->child[1];                
    }   
    else if(tmp->child[0]!=NULL)
    {
      tmp=tmp->child[0];                
    }                       
  }
  sponsor=tmp;
}

void tree :: reset_dh_counter() // Resets the number of DH actions performed after initial tree construction
{
  no_of_dh_actions = 0;
}
