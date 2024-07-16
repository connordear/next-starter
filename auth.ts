import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import { sql } from "@vercel/postgres";
import bcrypt from "bcrypt";
import { User } from "./app/lib/definitions";

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log(credentials);
        const validatedCreds = z
          .object({
            email: z.string().email({
              message: "Please enter a valid email address.",
            }),
            password: z.string().min(6, {
              message: "Password must be at least 6 characters long.",
            }),
          })
          .safeParse(credentials);
        if (validatedCreds.success) {
          const { email, password } = validatedCreds.data;
          const user = await getUser(email);
          console.log("User:", user);
          if (!user) return null;
          const passMatch = await bcrypt.compare(password, user.password);
          if (passMatch) return user;
        }
        console.log("Invalid credentials", validatedCreds.error);
        return null;
      },
    }),
  ],
});
