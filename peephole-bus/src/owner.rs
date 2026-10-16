//! "The owner of this well-known name must hold this role", and a watch for the name changing hands.

use crate::error::WhoError;
use crate::manager::UnitSource;
use crate::offload::Offload;
use crate::timeout::bounded;
use crate::who::BusPeers;
use peephole::ProcFs;
use peephole_core::{Refused, Requirement};
use std::future::poll_fn;
use std::pin::Pin;
use zbus::export::futures_core::Stream;
use zbus::fdo::{DBusProxy, NameOwnerChangedStream};
use zbus::names::OwnedUniqueName;

/// Ends when a well-known name changes owner. Subscribed before the owner was checked, so no
/// change falls between the question and the listening.
#[derive(Debug)]
pub struct OwnerWatch {
    stream: NameOwnerChangedStream,
}

impl OwnerWatch {
    /// Waits for the next change of owner. `None` when the bus connection closed (treat as a change).
    pub async fn changed(&mut self) -> Option<()> {
        poll_fn(|cx| Pin::new(&mut self.stream).poll_next(cx))
            .await
            .map(|_| ())
    }
}

impl<P: ProcFs + 'static, O: Offload, U: UnitSource> BusPeers<P, O, U> {
    /// The unique name that owns the well-known `name`, once its process meets one of `need`. A
    /// name nobody owns is a refusal, so a squatter that is absent cannot pass.
    pub async fn owner_of(
        &self,
        name: &str,
        need: &[Requirement],
    ) -> Result<OwnedUniqueName, Refused> {
        let owner = self.owner_name(name).await.map_err(|_| Refused::Unknown)?;
        self.require(Some(&owner), need).await?;
        OwnedUniqueName::try_from(owner).map_err(|_| Refused::Unknown)
    }

    /// Subscribes to changes of the owner of `name`. Call it before [`BusPeers::owner_of`].
    pub async fn watch_owner(&self, name: &str) -> Result<OwnerWatch, WhoError> {
        let bus = DBusProxy::new(&self.connection)
            .await
            .map_err(WhoError::Bus)?;
        let stream = bounded(bus.receive_name_owner_changed_with_args(&[(0, name)]))
            .await
            .map_err(|_| WhoError::Timeout)?
            .map_err(WhoError::Bus)?;
        Ok(OwnerWatch { stream })
    }
}
