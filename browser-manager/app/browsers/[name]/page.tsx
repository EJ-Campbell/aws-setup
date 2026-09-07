import { notFound } from "next/navigation";
import Desktop from "./desktop";

export default async function BrowserPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name)) notFound();
  return <Desktop name={name} />;
}
