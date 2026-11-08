import { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/api/"],
      },
    ],
    sitemap: "https://codefort-web.vercel.app/sitemap.xml",
    host: "https://codefort-web.vercel.app",
  };
}
