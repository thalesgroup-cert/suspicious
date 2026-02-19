import { Navigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/api/auth";

type Props = {
  children: React.ReactElement;
};

export default function ProtectedRoute({ children }: Props) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false
  });

  if (isLoading) {
    return null; // or a centered spinner
  }

  if (isError || !data) {
    return <Navigate to="/login" replace />;
  }

  return children;
}
