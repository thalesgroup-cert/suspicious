import { Navigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/api/auth";
import PageLoader from "@/styles/components/PageLoader";

type Props = {
  children: React.ReactElement;
};

/** Returns true when the non-httpOnly session_active cookie is present. */
function hasSessionCookie(): boolean {
  return document.cookie.split(";").some((c) => c.trim().startsWith("session_active="));
}

export default function PublicOnlyRoute({ children }: Props) {
  const maybeLoggedIn = hasSessionCookie();

  const { data, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: maybeLoggedIn,
  });

  if (maybeLoggedIn && isLoading) {
    return <PageLoader />;
  }

  if (data) {
    return <Navigate to="/" replace />;
  }

  return children;
}