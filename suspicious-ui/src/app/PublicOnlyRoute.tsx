import { Navigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/api/auth";

type Props = {
  children: React.ReactElement;
};

export default function PublicOnlyRoute({ children }: Props) {
  const token = localStorage.getItem("token");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !!token,
  });

  if (!token) {
    return children;
  }

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isError && data) {
    return <Navigate to="/" replace />;
  }

  return children;
}