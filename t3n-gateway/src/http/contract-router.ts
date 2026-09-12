import { Router } from 'express';
import type { PolicyEvaluationRequest, PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';

export function createContractRouter(service: PrivacyGuardContractService): Router {
  const router=Router();
  router.get('/identity',async(_req,res)=>{try{res.json({contractId:await service.canonicalContractId(),functions:['evaluate-action','execute-remediation']});}catch{res.status(503).json({error:'T3N contract identity is unavailable'});}});
  router.post('/evaluate',async(req,res)=>{try{res.json(await service.evaluate(req.body as Omit<PolicyEvaluationRequest,'agent_did'>));}catch{res.status(503).json({error:'Policy evaluation is unavailable'});}});
  router.post('/remediate',async(req,res)=>{try{res.json(await service.remediate(req.body as Omit<PolicyEvaluationRequest,'agent_did'|'host'>));}catch{res.status(503).json({error:'Protected remediation could not be completed'});}});
  return router;
}
