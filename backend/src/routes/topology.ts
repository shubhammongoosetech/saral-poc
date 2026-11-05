import { Router } from 'express';
import { requireAuth } from '../middleware/authGuard';
import {
  handleGetTopology,
  handleGetTopologyNodes,
  handleGetPlacement,
} from '../controllers/topologyController';

const router = Router();

router.get('/', handleGetTopology);
router.get('/nodes', handleGetTopologyNodes);
router.get('/placement', requireAuth, handleGetPlacement);

export default router;

