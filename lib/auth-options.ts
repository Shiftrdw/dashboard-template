import NextAuth from "next-auth";
import type { AuthOptions, User } from "next-auth";
import type { JWT } from "next-auth/jwt";
import CredentialsProvider from "next-auth/providers/credentials";
import axios from "axios";

import { jwtDecode } from "jwt-decode";

async function refreshAccessToken(token: JWT): Promise<JWT | null> {
  try {
    const res = await fetch(
      `${process.env.VITE_BASE_URL}/refresh/`,
      {
        method: "POST",
        body: JSON.stringify({ refresh: token.refresh }),
        headers: { "Content-Type": "application/json" },
      }
    );
    const refreshedToken: any = await res.json();

    if (res.status !== 200) throw refreshedToken;

    const { exp }: any = jwtDecode(refreshedToken.access);

    return {
      ...token,
      ...refreshedToken,
      exp,
    };
  } catch (error) {
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
}

export const authOptions: AuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  session: { strategy: "jwt" },
  // https://next-auth.js.org/configuration/providers/oauth
  pages: {
    signIn: "/", //sigin page
  },
  providers: [
    CredentialsProvider({
      // The name to display on the sign in form (e.g. 'Sign in with...')
      name: "Django Rest Framework",
      // The credentials is used to generate a suitable form on the sign in page.
      // You can specify whatever fields you are expecting to be submitted.
      // e.g. domain, username, password, 2FA token, etc.
      // You can pass any HTML attribute to the <input> tag through the object.
      credentials: {
        username: {
          label: "Username",
          type: "username",
          placeholder: "username",
        },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        try {
          const response = await axios({
            url: process.env.NEXTAUTH_BACKEND_URL + "login/",
            method: "post",
            data: credentials,
          });
          const data = response.data;
          if (data) return data;
        } catch (error) {
          console.error(error);
        }
        return null;
      },

    }),
  ],
  callbacks: {
    async redirect({ url, baseUrl }) {
    // Allows relative callback URLs
    if (url.startsWith("/")) return `${baseUrl}/dashboard`
    // Allows callback URLs on the same origin
    else if (new URL(url).origin === baseUrl) return url
    return baseUrl
  },
    async jwt({ token, user, account }: any) {
      console.log({ token, user, account })
      // initial signin
      if (user && account) {
        return user as JWT;
      }

      // Return previous token if the access token has not expired
      if (Date.now() < token.exp * 100) {
        return token;
      }

      // refresh token
      return (await refreshAccessToken(token)) as JWT;
    },
    async session({ session, token }: any) {
      console.log({ session, token })
      return session;
    },
  },
};
