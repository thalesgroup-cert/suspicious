// src/features/dashboard/api/topPrefixes.ts
export type TopPrefixesType = "user" | "group";

export interface TopPrefixApiItem {
    prefix: string;
    count: number;
}

export interface TopPrefixesResponse {
    type: TopPrefixesType;
    month?: string | null;
    year?: string | null;
    data: TopPrefixApiItem[];
}

export async function fetchTopPrefixes(params: {
    type: TopPrefixesType;
    month?: string;
    year?: string;
    limit?: number;
}): Promise<TopPrefixesResponse> {
    const search = new URLSearchParams();

    search.set("type", params.type);
    search.set("limit", String(params.limit ?? 10));

    if (params.month) search.set("month", params.month);
    if (params.year) search.set("year", params.year);

    const response = await fetch(`/api/stats/top-prefixes/?${search.toString()}`, {
        credentials: "include",
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch top prefixes (${response.status})`);
    }

    return response.json();
}