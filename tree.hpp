/* This program is for defining and constructing a tree */
//---Author -- Arjun <arjun2594@gmail.com>
#include<stdio.h>
#include<openssl/bn.h> //For BIGNUM datatype
#include<math.h> // For log2 
#include<openssl/dh.h> //For Diffie Hellman Protocol
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
    DH *dh;
    unsigned char *shared_key;
  } *root, *n, *temp,sopnsor;

  struct node* keypath[MAX_NODES+1];
  struct node* copath[MAX_NODES+1];
  int keypath_index,copath_index;
  struct node* sponsor;
  struct node_table
  {
    struct node *node [MAX_NODES];
    int nodeid [MAX_NODES];
  }nt;
  
  int no_of_leaves; // Stores the number of leaves in the tree
  int node_id_counter; // Stores the incremental id to be stored for the nodes.
  int nt_counter; // Index to the nodetable

 public:

  tree();
  node* create_node();
  int create_tree (int noofnodes); //Used for initially creating a tree;
  int add_to_tree (); // For adding a node or a set of nodes to a tree
  int delete_from_tree (int nodeid); // For deleting a node or a set of nodes from a tree;
  int set_keys ();
  int get_max_id();
  node* find_node_by_id (int nodeid);
  void insert_into_node_table (node *node, int nodeid);
  void delete_from_node_table (int nodeid);
  int keygen(node *); // For generating the keys for a particular node
  int compute_shared_key(node *); // For computing the shared key at each node
  node* get_sibling(node *e); // For getting the sibling of each node
  int tree_height();
        
  void keypath_reset(node *n);
  void copath_reset(node *n);
  void print(node *n);
  void inorder(node *n);
  void preorder(node *n);
  node* getkeypath(node *n);
  node* getcopath(node *n);
  void add_keypath(node *n);
  void add_copath(node *n);
  void print_keypath();
  void print_copath();
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
 
}

int tree :: tree_height()
{
  return int(floor(log2(no_of_leaves)));
}
  
tree :: node* tree :: create_node ()
{
  n = new node;
  no_of_leaves++;
  n -> nodeid = node_id_counter++;
  insert_into_node_table (n, n->nodeid);
  keygen(n);
}

int tree :: add_to_tree () // Method is used for adding nodes to the key tree
{

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
    temp -> parent = inter -> parent; // Make this node to point to the parent of the original node
    temp -> child[0] = inter; // Make the original node its child
    inter -> parent = temp; // Make the new node its parent
    temp -> child[1] = n; // Make the incoming node the child of the newly created node
    n -> parent = inter;
  }

  else
  {
    temp = find_node_by_id(get_max_id()); //Get the rightmost node;
    node *inter = temp -> parent;
    inter -> child[1] = n; // Assign this node as the parent of the shallowest rightmost node;
  }
}

int tree:: delete_from_tree(int nodeid) // Delete a node from tree - Takes nodeid as input
{
  temp = find_node_by_id (nodeid);

  if (temp == NULL)
    return -1; 

  else
  {
    temp -> parent = get_sibling(temp);
    delete_from_node_table(temp -> nodeid); // Delete the entry from node table also
    delete temp;
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
  return node_id_counter;
}

void tree :: insert_into_node_table (node *node, int nodeid) // inserting a node into the node table
{
  nt.node[nt_counter] = node;
  nt.nodeid[nt_counter++] = nodeid;
}
    
void tree :: delete_from_node_table (int nodeid)
{
  for (int i = 0; i<no_of_leaves; i++)
    if(nt.nodeid[i] == nodeid)
    {
      nt.nodeid[i] = -1; //set invalid nodeid
      nt.node[i] = NULL; 
    }
}

int tree :: keygen(node *n)
{
  return DH_generate_key(n -> dh);
}

int tree :: compute_shared_key(node *n)
{
  node *sibling = get_sibling(n);
  return DH_compute_key(n -> shared_key, (sibling -> dh) -> pub_key, n -> dh); // Compute the key for each node.
}

tree :: node* tree :: get_sibling(node *n) // Method to get the 
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
  print_keypath();
}

tree :: node* tree :: getcopath(node *n)
{
  copath_reset(n);
  add_copath(n);
  print_copath();
}

void tree :: add_keypath(node *n)
{
  while(n!=NULL)
  {
    keypath [++keypath_index] = n;
    n = n -> parent;            
  }
  keypath[keypath_index+1] = NULL;
}

void tree :: add_copath(node *n)
{     
  while((n->parent)!=NULL)
  {
    copath[copath_index] = get_sibling(n); 
    n=n->parent;            
  }
  copath[copath_index+1]=NULL;
}
  
void tree :: print_keypath()
{
  printf("\n nodes in key path : ");
  for(int i=0;i<=keypath_index;i++)
  {
    printf("%d",keypath[i]->nodeid);
  }
}

void tree :: print_copath()
{
  printf("\n nodes in co path : ");
  for(int i=0;i<=copath_index;i++)
  {
    printf("%d",copath[i]->nodeid);
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
