/* app */
export enum SystemInputEnum {
  'welcomeText' = 'welcomeText',
  'variables' = 'variables',
  'switch' = 'switch', // a trigger switch
  'history' = 'history',
  'userChatInput' = 'userChatInput',
  'questionGuide' = 'questionGuide',
  isResponseAnswerText = 'isResponseAnswerText'
}
export enum SystemOutputEnum {
  finish = 'finish'
}

export enum VariableInputEnum {
  input = 'input',
  select = 'select'
}

export enum AppTypeEnum {
  basic = 'basic',
  advanced = 'advanced'
}
