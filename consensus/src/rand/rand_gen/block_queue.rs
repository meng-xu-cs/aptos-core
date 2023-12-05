// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::experimental::buffer_manager::OrderedBlocks;
use aptos_consensus_types::{
    common::Round,
    executed_block::ExecutedBlock,
    randomness::{RandMetadata, Randomness},
};
use std::collections::{BTreeMap, HashMap};

/// Maintain the ordered blocks received from consensus and corresponding randomness
pub struct QueueItem {
    ordered_blocks: OrderedBlocks,
    offsets_by_round: HashMap<Round, usize>,
    num_undecided_blocks: usize,
}

impl QueueItem {
    pub fn new(ordered_blocks: OrderedBlocks) -> Self {
        let len = ordered_blocks.ordered_blocks.len();
        assert!(len > 0);
        let offsets_by_round: HashMap<Round, usize> = ordered_blocks
            .ordered_blocks
            .iter()
            .enumerate()
            .map(|(idx, b)| (b.round(), idx))
            .collect();
        Self {
            ordered_blocks,
            offsets_by_round,
            num_undecided_blocks: len,
        }
    }

    pub fn num_blocks(&self) -> usize {
        self.blocks().len()
    }

    pub fn first_round(&self) -> u64 {
        self.blocks().first().unwrap().block().round()
    }

    pub fn offset(&self, round: Round) -> usize {
        *self.offsets_by_round.get(&round).unwrap()
    }

    pub fn num_undecided(&self) -> usize {
        self.num_undecided_blocks
    }

    pub fn rand_metadata(&self, round: Round) -> RandMetadata {
        let block = self.blocks()[self.offset(round)].block();
        block.into()
    }

    pub fn set_randomness(&mut self, round: Round, rand: Randomness) -> bool {
        let offset = self.offset(round);
        if !self.blocks()[offset].has_randomness() {
            self.blocks_mut()[offset].set_randomness(rand);
            self.num_undecided_blocks -= 1;
            true
        } else {
            false
        }
    }

    fn blocks(&self) -> &[ExecutedBlock] {
        &self.ordered_blocks.ordered_blocks
    }

    fn blocks_mut(&mut self) -> &mut [ExecutedBlock] {
        &mut self.ordered_blocks.ordered_blocks
    }
}

/// Maintain ordered blocks that have pending randomness
pub struct BlockQueue {
    queue: BTreeMap<Round, QueueItem>,
}
impl BlockQueue {
    pub fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
        }
    }

    pub fn push_back(&mut self, item: QueueItem) {
        assert!(self.queue.insert(item.first_round(), item).is_none());
    }

    /// Dequeue all ordered blocks prefix that have randomness
    pub fn dequeue_rand_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut rand_ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.num_undecided() == 0 {
                let (_, item) = self.queue.pop_first().unwrap();
                let QueueItem { ordered_blocks, .. } = item;
                debug_assert!(ordered_blocks
                    .ordered_blocks
                    .iter()
                    .all(|block| block.has_randomness()));
                rand_ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        rand_ready_prefix
    }

    /// Return the `QueueItem` that contains the given round, if exists.
    pub fn item_mut(&mut self, round: Round) -> Option<&mut QueueItem> {
        self.queue
            .range_mut(0..=round)
            .last()
            .map(|(_, item)| item)
            .filter(|item| item.offsets_by_round.contains_key(&round))
    }

    /// Update the corresponding block's randomness, return true if updated successfully
    pub fn set_randomness(&mut self, round: Round, randomness: Randomness) -> bool {
        if let Some(item) = self.item_mut(round) {
            item.set_randomness(round, randomness)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        experimental::buffer_manager::OrderedBlocks,
        rand::rand_gen::block_queue::{BlockQueue, QueueItem},
    };
    use aptos_consensus_types::{
        block::Block,
        block_data::{BlockData, BlockType},
        common::Round,
        executed_block::ExecutedBlock,
        quorum_cert::QuorumCert,
        randomness::Randomness,
    };
    use aptos_crypto::HashValue;
    use aptos_executor_types::StateComputeResult;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    use std::collections::HashSet;

    fn create_ordered_blocks(rounds: Vec<Round>) -> OrderedBlocks {
        let blocks = rounds
            .into_iter()
            .map(|round| {
                ExecutedBlock::new(
                    Block::new_for_testing(
                        HashValue::random(),
                        BlockData::new_for_testing(
                            1,
                            round,
                            1,
                            QuorumCert::dummy(),
                            BlockType::Genesis,
                        ),
                        None,
                    ),
                    vec![],
                    StateComputeResult::new_dummy(),
                )
            })
            .collect();
        OrderedBlocks {
            ordered_blocks: blocks,
            ordered_proof: LedgerInfoWithSignatures::new(
                LedgerInfo::mock_genesis(None),
                AggregateSignature::empty(),
            ),
            callback: Box::new(move |_, _| {}),
        }
    }
    #[test]
    fn test_queue_item() {
        let single_round = vec![1];
        let mut item = QueueItem::new(create_ordered_blocks(single_round));
        assert_eq!(item.num_blocks(), 1);
        assert_eq!(item.offset(1), 0);
        assert_eq!(item.num_undecided(), 1);
        item.set_randomness(1, Randomness::default());
        assert_eq!(item.num_undecided(), 0);

        let multiple_rounds = vec![1, 2, 3, 5, 8, 13, 21, 34];
        let mut item = QueueItem::new(create_ordered_blocks(multiple_rounds.clone()));
        assert_eq!(item.num_blocks(), multiple_rounds.len());
        assert_eq!(item.num_undecided(), item.num_blocks());
        for (idx, round) in multiple_rounds.iter().enumerate() {
            assert_eq!(item.offset(*round), idx);
            assert!(item.set_randomness(*round, Randomness::default()));
            // double update doesn't reduce the count
            assert!(!item.set_randomness(*round, Randomness::default()));
            assert_eq!(item.num_undecided(), item.num_blocks() - idx - 1);
        }
    }

    #[test]
    fn test_block_queue() {
        let mut queue = BlockQueue::new();
        let all_rounds = vec![vec![1], vec![2, 3], vec![5, 8, 13], vec![21, 34, 55]];
        for rounds in &all_rounds {
            queue.push_back(QueueItem::new(create_ordered_blocks(rounds.clone())));
        }

        let exists_rounds: HashSet<_> = all_rounds.iter().flatten().collect();

        // find the right item
        for round in 0..100 {
            assert_eq!(
                queue
                    .item_mut(round)
                    .map_or(false, |item| item.offsets_by_round.contains_key(&round)),
                exists_rounds.contains(&round)
            );
        }

        // update non existing round
        assert!(!queue.set_randomness(10, Randomness::default()));

        // dequeue first ready one
        assert!(queue.set_randomness(1, Randomness::default()));
        // update twice
        assert!(!queue.set_randomness(1, Randomness::default()));
        assert_eq!(queue.dequeue_rand_ready_prefix().len(), 1);

        // not dequeue undecided batch
        queue.set_randomness(2, Randomness::default());
        assert_eq!(queue.dequeue_rand_ready_prefix().len(), 0);

        // not dequeue undecided prefix
        queue.set_randomness(5, Randomness::default());
        queue.set_randomness(8, Randomness::default());
        queue.set_randomness(13, Randomness::default());
        assert_eq!(queue.dequeue_rand_ready_prefix().len(), 0);

        queue.set_randomness(3, Randomness::default());
        assert_eq!(queue.dequeue_rand_ready_prefix().len(), 2);

        assert_eq!(queue.queue.len(), 1);
    }
}