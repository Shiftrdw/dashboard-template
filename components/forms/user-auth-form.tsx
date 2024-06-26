"use client";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { zodResolver } from "@hookform/resolvers/zod";
import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { Loader2 } from "lucide-react"

const formSchema = z.object({
  email: z.string().email({ message: "Enter a valid email address" }),
  password: z.string()
});

type UserFormValue = z.infer<typeof formSchema>;

export default function UserAuthForm() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const [loading, setLoading] = useState(false);
  const defaultValues = {
    email: "",
    password: ""
  };
  const form = useForm<UserFormValue>({
    resolver: zodResolver(formSchema),
    defaultValues,
  });

  function timer(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  const onSubmit = async (data: UserFormValue) => {
    try {
      setLoading(true);
      
      signIn("credentials", {
        email: data.email,
        password: data.password,
        callbackUrl,
      });
      await timer(2000);
    } catch (error) {
      console.log(error)
    } finally {
      setLoading(false);
    }
  };

  return (
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="space-y-2 w-full"
        >
          <FormField
            control={form.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email</FormLabel>
                <FormControl>
                  <Input
                    type="email"
                    placeholder="Enter your email..."
                    disabled={form.formState.isSubmitting}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password</FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder="Enter your password..."
                    disabled={form.formState.isSubmitting}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <div>
            <Button disabled={loading} className="w-full mt-5" type="submit">
              {loading ?<Loader2 className="mr-2 h-4 w-4 animate-spin" />: null}
              {"Login"}
            </Button>
          </div>          
        </form>
      </Form>
  );
}
