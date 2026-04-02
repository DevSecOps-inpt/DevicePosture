import { EndpointDetailPage } from "@/components/modules/endpoints/endpoint-detail-page";

export default function EndpointDetailRoute({ params }: { params: { id: string } }) {
  return <EndpointDetailPage endpointId={params.id} />;
}
