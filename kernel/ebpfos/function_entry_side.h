/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_SIDE_H
#define EBPFOS_FUNCTION_ENTRY_SIDE_H
#include <linux/rbtree.h>
/* A side field is shared state of the original object. A same-layout update
 * cannot silently replace it with a fresh initialized map. All work is cold;
 * programs retain their ordinary direct map-value accesses.
 */
struct entry_side_cell {
 struct rb_node node;
 const char *key;
 struct bpf_map *before,*after;
};
struct entry_side_index {struct rb_root root;bool before,migration;};
static int entry_side_program(struct bpf_prog *program,void *data)
{
 struct entry_side_index *index=data;struct bpf_prog_aux *aux=program->aux;
 unsigned int i;int error=0;
 mutex_lock(&aux->used_maps_mutex);
 for(i=0;i<aux->used_map_cnt;++i) {
  struct bpf_map *map=aux->used_maps[i];
  const struct btf_type *section;
  const char *key;struct rb_node **link=&index->root.rb_node,*parent=NULL;
  struct entry_side_cell *cell=NULL;
  if(!map->btf)continue;
  section=btf_type_by_id(map->btf,map->btf_value_type_id);
  if(!section||BTF_INFO_KIND(section->info)!=BTF_KIND_DATASEC)continue;
  key=btf_name_by_offset(map->btf,section->name_off);
  if(strncmp(key,".data.side.",11))continue;
  while(*link) {
   int order;
   parent=*link;cell=rb_entry(parent,struct entry_side_cell,node);
   order=strcmp(key,cell->key);
   if(!order)break;
   link=order<0?&parent->rb_left:&parent->rb_right;cell=NULL;
  }
  if(!cell) {
   cell=kzalloc(sizeof(*cell),GFP_KERNEL);
   if(!cell){error=-ENOMEM;break;}
   cell->key=key;rb_link_node(&cell->node,parent,link);rb_insert_color(&cell->node,&index->root);
  }
  if(index->before) {
   if(cell->before&&cell->before!=map){error=-EXDEV;break;}
   cell->before=map;
  } else {
   if((cell->after&&cell->after!=map)||
      (!index->migration&&cell->before&&cell->before!=map)){error=-EXDEV;break;}
   cell->after=map;
  }
 }
 mutex_unlock(&aux->used_maps_mutex);return error;
}
static int entry_side_members(struct entry_set *set,unsigned int slot,struct entry_side_index *index)
{
 unsigned int i;int error;
 for(i=0;set&&i<set->count;++i) {
  error=entry_side_program(set->programs[i*2+slot],index);if(error)return error;
 }
 return set?bpf_operations_visit_programs(set->tables,entry_side_program,index):0;
}
static int entry_side_compatible(struct entry_set *before,unsigned int slot,
 struct entry_set *after,bool migration)
{
 struct entry_side_index index={.root=RB_ROOT,.before=true,.migration=migration};
 struct rb_node *node;int error;
 /* Retained program references own every indexed map and BTF key. */
 error=entry_side_members(before,slot,&index);
 if(!error){index.before=false;error=entry_side_members(after,0,&index);}
 while((node=rb_first(&index.root))) {
  struct entry_side_cell *cell=rb_entry(node,struct entry_side_cell,node);
  rb_erase(node,&index.root);kfree(cell);
 }
 return error;
}
#endif
