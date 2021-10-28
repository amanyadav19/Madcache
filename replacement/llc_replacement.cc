#include "cache.h"

// initialize replacement state
void CACHE::llc_initialize_replacement()
{

}

// find replacement victim
uint32_t CACHE::llc_find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{
    // baseline LRU
    bool default_policy; // false if lru , true if bypass
    if(set_dueling_counter >= (1<<9)) {
        default_policy = true; // bypass
    }
    else {
        default_policy = false; // lru
    }
    if(default_policy) {
        set_dueling_counter = min(set_dueling_counter+1, (1<<10)-1);
    }
    else {
        set_dueling_counter = max(set_dueling_counter-1, 0);
    }

    bool new_default_policy;
    if(set_dueling_counter >= (1<<9)) {
        new_default_policy = true; // bypass
    }
    else {
        new_default_policy = false; // lru
    }

    uint32_t way = 0;
    if(set < LLC_TRACKER_SET) {
        // in tracker set
        for (way=0; way<NUM_WAY; way++) {
            if (block[set][way].valid == false) {

                DP ( if (warmup_complete[cpu]) {
                cout << "[" << NAME << "] " << __func__ << " instr_id: " << instr_id << " invalid set: " << set << " way: " << way;
                cout << hex << " address: " << (full_addr>>LOG2_BLOCK_SIZE) << " victim address: " << block[set][way].address << " data: " << block[set][way].data;
                cout << dec << " lru: " << block[set][way].lru << endl; });

                break;
            }
        }

        if (way != NUM_WAY) {
            // cache line is empty(found 1 invalid block)
            int loc1 = -1, loc2 = -1;
            for(int i = 0; i < PC_PREDICTOR_SIZE; i++) {
                if(pc_predictor[i].policy == new_default_policy && pc_predictor[i].pc == ip) {
                    loc1 = i;
                    break;
                }
            }
            if(loc1 == -1) {
                // no entry corresponding to that pc in the pc predictor table
                for(int i = 0; i < PC_PREDICTOR_SIZE; i++) {
                    if(pc_predictor[i].valid == false) {
                        loc2 = i;
                        break;
                    }
                }
                if(loc2 != -1) {
                    // pc predictor table has empty space
                    pc_predictor[loc2].policy = new_default_policy;
                    pc_predictor[loc2].pc = ip;
                    pc_predictor[loc2].counter = (1<<5) - 1; // 0111111111
                    pc_predictor[loc2].num_entries = 1;
                    pc_predictor[loc2].valid = true;
                    // set the index and resuse bit in tracker set block
                    block[set][way].PC_pred_table_index = loc2;
                    block[set][way].reuse = false;
                    // we want to now fill that chache line with this missed cache so we return way
                    return way;
                }
                else {
                    // pc predictor table has no empty space
                    // so we just insert the cache line without creating any entry in predictor table
                    block[set][way].PC_pred_table_index = -1;
                    block[set][way].reuse = false;
                    return way;
                }
            }
            else {
                // entry in predictor table found
                pc_predictor[loc1].num_entries += 1;
                // set the index and resuse bit in tracker set block
                block[set][way].PC_pred_table_index = loc1;
                block[set][way].reuse = false;
                return way;
            }

        }
        else {
            // cache is full we need to evict something or bypass
            int loc1 = -1, loc2 = -1;
            for(int i = 0; i < PC_PREDICTOR_SIZE; i++) {
                if(pc_predictor[i].policy == false && pc_predictor[i].pc == ip) {
                    loc1 = i;
                    break;
                }
            }
            if(loc1 == -1) {
                // no entry corresponding to that pc in the pc predictor table
                for(int i = 0; i < PC_PREDICTOR_SIZE; i++) {
                    if(pc_predictor[i].valid == false) {
                        loc2 = i;
                        break;
                    }
                }
                if(loc2 != -1) {
                    // predictor table has empty space
                    pc_predictor[loc2].policy = new_default_policy;
                    pc_predictor[loc2].pc = ip;
                    pc_predictor[loc2].counter = (1<<5) - 1; // 011111
                    pc_predictor[loc2].num_entries = 1;
                    pc_predictor[loc2].valid = true;
                    // set the index and resuse bit in tracker set block
                    // add the block using lru
                    way = lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type);
                    // make sure to decrement num entries of this evicted cache
                    if(block[set][way].PC_pred_table_index !=-1) {
                        pc_predictor[block[set][way].PC_pred_table_index].counter = min(pc_predictor[block[set][way].PC_pred_table_index].counter+1, (1<<6)-1);
                        pc_predictor[block[set][way].PC_pred_table_index].num_entries -= 1;
                        if(pc_predictor[block[set][way].PC_pred_table_index].num_entries <=0) {
                            pc_predictor[block[set][way].PC_pred_table_index].valid = false;
                        }
                    }
                    block[set][way].PC_pred_table_index = loc2;
                    block[set][way].reuse = false;
                    // we want to now fill that chache line with this missed cache so we return way
                    return way;
                }
                else {
                    // predictor table has no empty space
                    // follow default policy
                    if(new_default_policy) return NUM_WAY;
                    else {
                        way = lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type);
                        if(block[set][way].PC_pred_table_index !=-1) {
                            pc_predictor[block[set][way].PC_pred_table_index].counter = min(pc_predictor[block[set][way].PC_pred_table_index].counter+1, (1<<6)-1);
                            pc_predictor[block[set][way].PC_pred_table_index].num_entries -= 1;
                            if(pc_predictor[block[set][way].PC_pred_table_index].num_entries <=0) {
                                pc_predictor[block[set][way].PC_pred_table_index].valid = false;
                            }
                        }
                        block[set][way].PC_pred_table_index = -1;
                        block[set][way].reuse = false;
                        return way;
                    }
                }
            }
            else {
                // entry corresponding to that pc found in pc predictor table
                // we read the counter and get the policy
                if(pc_predictor[loc1].counter >= 1<<5) {
                    // use lru policy now
                    pc_predictor[loc1].num_entries += 1;
                    way = lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type);
                    return way;
                }
                else {
                    // bypass
                    return NUM_WAY;
                }
            }
        }
    }
    else {
        // we are in follower sets
        // we don't update the pc predictor table and just follow the default policy as decided by the tracker sets or the overriden policy when there is pc_predictor hit
        int loc1 = -1;
        for(int i = 0; i < PC_PREDICTOR_SIZE; i++) {
            if(pc_predictor[i].policy == new_default_policy && pc_predictor[i].pc == ip) {
                loc1 = i;
                break;
            }
        }
        if(loc1 == -1) {
            // no entry corresponding to that pc in the pc predictor table
            // follow default policy as decided by set dueling
            if(new_default_policy) return NUM_WAY;
            else return lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type);
        }
        else {
            // we found the entry in pc predictor
            if(pc_predictor[loc1].counter >= 1<<5) {
                // use lru policy now
                return lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type);
            }
            else {
                // bypass
                return NUM_WAY;
            }
        }
    }
    // shouldn't reach here
    assert(0);
}

// called on every cache hit and cache fill
void CACHE::llc_update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit)
{
    string TYPE_NAME;
    if (type == LOAD)
        TYPE_NAME = "LOAD";
    else if (type == RFO)
        TYPE_NAME = "RFO";
    else if (type == PREFETCH)
        TYPE_NAME = "PF";
    else if (type == WRITEBACK)
        TYPE_NAME = "WB";
    else
        assert(0);

    if (hit)
        TYPE_NAME += "_HIT";
    else
        TYPE_NAME += "_MISS";

    if ((type == WRITEBACK) && ip)
        assert(0);

    // uncomment this line to see the LLC accesses
    // cout << "CPU: " << cpu << "  LLC " << setw(9) << TYPE_NAME << " set: " << setw(5) << set << " way: " << setw(2) << way;
    // cout << hex << " paddr: " << setw(12) << paddr << " ip: " << setw(8) << ip << " victim_addr: " << victim_addr << dec << endl;

    // baseline LRU
    if (hit && (type == WRITEBACK)) // writeback hit does not update LRU state
        return;

    return lru_update(set, way);
}

void CACHE::llc_replacement_final_stats()
{

}
