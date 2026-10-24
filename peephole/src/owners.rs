//! Who a file's owner number names, as this process's user namespace shows it.
//!
//! A user service with `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=` and the like runs with
//! `PrivateUsers=self`: only the person's own uid is mapped, and root (with every other account)
//! shows as the kernel's overflow uid. Read as it stands, every system file then looks owned by
//! uid 65534 and nothing is root-only, so such a service could prove no peer at all. Where root
//! is not mapped, an owner equal to the overflow uid is taken as root's. The person's own uid is
//! still mapped, so a file they own is still theirs; the write bits for group and others show
//! through the namespace and still count.

/// How this process's user namespace shows file owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerView {
    /// Root is mapped (the initial namespace, or one that maps it): an owner is who it says.
    AsSeen,
    /// Root is not mapped: root and every other unmapped account show as `overflow`, and such a
    /// file is taken as root's.
    RootUnmapped {
        /// The kernel's overflow uid (`/proc/sys/kernel/overflowuid`).
        overflow: u32,
    },
}

/// One line of a `uid_map`: `count` ids from `inside` in the namespace are `outside`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    inside: u64,
    outside: u64,
    count: u64,
}

impl Range {
    fn parse(line: &str) -> Option<Range> {
        let mut numbers = line.split_whitespace().map(|n| n.parse::<u64>().ok());
        let range = Range {
            inside: numbers.next()??,
            outside: numbers.next()??,
            count: numbers.next()??,
        };
        numbers.next().is_none().then_some(range)
    }

    fn maps_outside(&self, id: u64) -> bool {
        id >= self.outside && id - self.outside < self.count
    }

    fn maps_inside(&self, id: u64) -> bool {
        id >= self.inside && id - self.inside < self.count
    }
}

impl OwnerView {
    /// The view the namespace whose `uid_map` and `overflowuid` files read so gives. Anything
    /// unreadable, and an overflow uid that is itself mapped (it would then name a real account),
    /// keeps owners as they are seen: the strict reading.
    ///
    /// ```
    /// use peephole::OwnerView;
    ///
    /// let initial = "         0          0 4294967295\n";
    /// assert_eq!(OwnerView::of(initial, "65534\n"), OwnerView::AsSeen);
    /// let user_service = "      1000       1000          1\n";
    /// assert_eq!(
    ///     OwnerView::of(user_service, "65534\n"),
    ///     OwnerView::RootUnmapped { overflow: 65534 }
    /// );
    /// ```
    pub fn of(uid_map: &str, overflowuid: &str) -> OwnerView {
        let ranges: Option<Vec<Range>> = uid_map
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(Range::parse)
            .collect();
        let (Some(ranges), Ok(overflow)) = (ranges, overflowuid.trim().parse::<u32>()) else {
            return OwnerView::AsSeen;
        };
        let root_mapped = ranges.iter().any(|range| range.maps_outside(0));
        let overflow_mapped = ranges
            .iter()
            .any(|range| range.maps_inside(u64::from(overflow)));
        match (ranges.is_empty(), root_mapped, overflow_mapped) {
            (false, false, false) => OwnerView::RootUnmapped { overflow },
            _ => OwnerView::AsSeen,
        }
    }

    /// The owner `uid` as a file's trust should name it: root for the overflow uid where root is
    /// not mapped, else `uid`.
    pub fn owner(self, uid: u32) -> u32 {
        match self {
            OwnerView::RootUnmapped { overflow } if uid == overflow => 0,
            _ => uid,
        }
    }
}
