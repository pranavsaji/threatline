import { memoryFeedbackRepo, memorySuppressionRepo } from '../fakes/index.js';
import { suppressionContract } from './suppressions.contract.js';

suppressionContract('memory', { suppressions: async () => memorySuppressionRepo(), feedback: async () => memoryFeedbackRepo() });
