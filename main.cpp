#include "tree.hpp"
#include<stdio.h>

int main()
{
  tree t;
  int n,ch=1, del;
  printf("\nEnter the number of nodes to be in the initial tree");
  scanf("%d",&n);
  t.create_tree(n);
  printf("--------------------------------------------------------------------------------\n");
  printf("Hit Ctrl-D to exit\n");
  printf("--------------------------------------------------------------------------------\n");
  while(true) 
  {
    printf("\n(i)nsertion or (d)eletion");
    ch = getchar();
    if(ch == 'i')
      t.add_to_tree();
    else if(ch == 'd')
    {
      printf("Enter the nodeid to be deleted: ");
      scanf("%d", del);
      t.delete_from_tree(del);
    }
  }
  printf("Total no of broadcasts: %d\n", t.get_broadcast_count());
  printf("Total no of messages: %d\n", t.get_message_count());
  printf("Total no_of_DH_operatons: %d\n", t.get_no_of_dh_actions());
  return ch;
}
