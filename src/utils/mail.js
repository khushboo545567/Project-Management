import Mailgen from "mailgen";
import nodemailer from "nodemailer";

// SEND THE EMAIL
const sendMail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task management",
      link: "websiteLinkTaskMngnt",
    },
  });

  const emailTaxtual = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailhtml = mailGenerator.generate(options.mailgenContent);

  const transpoartor = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.taskmanager.com@gamil.com",
    to: options.email,
    subject: options.subject,
    text: emailTaxtual,
    html: emailhtml,
  };

  try {
    await transpoartor.sendMail(mail);
  } catch (err) {
    console.err(
      "email survice failed.Make sure that you have provided your MAILTRAP crediancial in the .env file",
    );
    console.error("Error", err);
  }
};

// generate the mail
const emailVerificationContent = (userName, verificationurl) => {
  return {
    body: {
      name: userName,
      intro: "welcome to our app we are exicted to have you on board",
      action: {
        instructions: "To veriy you email please click on the button ",
        button: {
          color: "#1aae",
          text: "verify your email",
          link: verificationurl,
        },
      },
      outro:
        "Need help or any question , just reply to this email we would love to help you ",
    },
  };
};

const forgetPasswordMailgenContent = (userName, passwordResetUrl) => {
  return {
    body: {
      name: userName,
      intro: "we got request to reset your password",
      action: {
        instructions: "To reset your passwrod click on the following button ",
        button: {
          color: "#1aae",
          text: "Reset passwrod",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help or any question , just reply to this email we would love to help you ",
    },
  };
};

export { forgetPasswordMailgenContent, emailVerificationContent, sendMail };
