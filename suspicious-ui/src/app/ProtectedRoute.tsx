import * as React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/api/auth";
import PageLoader from "@/styles/components/PageLoader";

type Props = {
  children: React.ReactElement;

  /**
   * Optional role gate. If provided, the user must belong to at least
   * one of these groups — otherwise they are redirected to "/".
   * Example: <ProtectedRoute requireGroups={["CERT", "Admin"]}>
   */
  requireGroups?: string[];
};

export default function ProtectedRoute({ children, requireGroups }: Props) {
  const location = useLocation();

  const { data: me, isLoading, isError } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  if (isLoading) {
    return <PageLoader />;
  }

  if (isError || !me) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  if (requireGroups && requireGroups.length > 0) {
    const groups: string[] = (me as any)?.groups ?? [];
    const hasAccess = requireGroups.some((g) => groups.includes(g));
    if (!hasAccess) {
      return <Navigate to="/" replace />;
    }
  }

  return children;
}