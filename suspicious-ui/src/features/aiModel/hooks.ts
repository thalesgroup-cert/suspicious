import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import * as api from "./api";
import { refusalMessage, type RefusalContext } from "./labels";
import { aiModelKeys } from "./queryKeys";

/** Only the status polls (Ruling G12); the rest refetch on focus and on the Settings Refresh. */
export const useAiModelStatus = () =>
  useQuery({
    queryKey: aiModelKeys.status(),
    queryFn: api.getStatus,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
    retry: false,
    staleTime: 15_000,
  });

const list = <T>(key: (p?: api.PageParams) => readonly unknown[], fn: (p?: api.PageParams) => Promise<T>) =>
  (params?: api.PageParams) => useQuery({ queryKey: key(params), queryFn: () => fn(params), retry: false });

export const useAiModelVersions = list(aiModelKeys.versions, api.getVersions);
export const useAiModelCandidates = list(aiModelKeys.candidates, api.getCandidates);
export const useAiModelShadow = list(aiModelKeys.shadow, api.getShadow);
export const useAiModelReviews = list(aiModelKeys.reviews, api.getReviews);
export const useAiModelFlags = list(aiModelKeys.flags, api.getFlags);
export const useAiModelQueue = list(aiModelKeys.queue, api.getQueue);
export const useAiModelLedger = () => useQuery({ queryKey: aiModelKeys.ledger(), queryFn: api.getLedger, retry: false });

/** Jobs poll every 10 s only while a job runs. */
export const useAiModelJobs = (jobRunning: boolean, params?: api.PageParams) =>
  useQuery({
    queryKey: aiModelKeys.jobs(params),
    queryFn: () => api.getJobs(params),
    retry: false,
    refetchInterval: jobRunning ? 10_000 : false,
  });

/** A write refreshes the whole card; a refusal is shown in words and leaves the cache as the server has it. */
function useWrite<V, R>(fn: (v: V) => Promise<R>, context: RefusalContext = "action") {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => qc.invalidateQueries({ queryKey: aiModelKeys.all }),
    onError: (e) => {
      enqueueSnackbar(refusalMessage(e, context), { variant: "error" });
      // A refusal means the server state differs from what the card showed.
      void qc.invalidateQueries({ queryKey: aiModelKeys.all });
    },
  });
}

export const useRetrain = () => useWrite(api.postRetrain, "retrain");
export const useShadowStart = () => useWrite(api.postShadowStart);
export const usePromote = () => useWrite(api.postPromote);
export const useRollback = () => useWrite(api.postRollback);
export const useDiscard = () => useWrite(api.postDiscard);
export const useExtend = () => useWrite(api.postExtend);
export const useRecheck = () => useWrite(api.postRecheck);
export const useReview = () => useWrite(api.postReview);
export const useResolveFlag = () => useWrite(api.postResolveFlag);
export const useResetBreaker = () => useWrite(api.postResetBreaker, "breaker");
