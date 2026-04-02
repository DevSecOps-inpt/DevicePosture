import { PolicyDetailPage } from "@/components/modules/policies/policy-detail-page";

export default function PolicyDetailRoute({ params }: { params: { id: string } }) {
  return <PolicyDetailPage policyId={params.id} />;
}
