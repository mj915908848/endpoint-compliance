import type { Session } from "./types";

export const role = (session: Session, name: string) => session.roles.includes(name);
