import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto flex max-w-xl flex-col items-center px-4 py-32 text-center">
      <p className="text-sm font-medium text-indigo-300">404</p>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">Page not found</h1>
      <p className="mt-3 text-slate-400">The page you&apos;re looking for doesn&apos;t exist.</p>
      <Link
        href="/"
        className="mt-8 rounded-xl bg-indigo-500 px-5 py-2.5 font-medium text-white transition hover:bg-indigo-400"
      >
        Back to the scanner
      </Link>
    </div>
  );
}
