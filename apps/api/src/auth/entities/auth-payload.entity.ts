import { Field, Int, ObjectType } from "@nestjs/graphql";


@ObjectType()
export class AuthPayload{
    @Field(() => Int)
    id: number;

    @Field()
    name: string;
    
    @Field()
    email: string;

    @Field({ nullable: true })
    avatar?: string;

    @Field()
    accessToken: string;
}