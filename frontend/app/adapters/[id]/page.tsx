import { AdapterDetailPage } from "@/components/modules/adapters/adapter-detail-page";

export default function AdapterDetailRoute({ params }: { params: { id: string } }) {
  return <AdapterDetailPage adapterId={params.id} />;
}
