import { notFound } from "next/navigation";
import Viewer from "./viewer";

export default async function BrowserPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(name)) notFound();
  return <Viewer name={name} />;
}
