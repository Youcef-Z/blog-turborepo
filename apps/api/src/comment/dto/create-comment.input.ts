import { InputType, Int, Field } from '@nestjs/graphql';

@InputType()
export class CreateCommentInput {
  @Field(() => Int, { description: 'Example field (placeholder)' })
  exampleField: number;
}
